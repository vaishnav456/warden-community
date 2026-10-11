import {test} from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {mkdtemp,rm,readFile,writeFile,stat,appendFile,rename} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {FileCheckpoint} from '../checkpoint.mjs';
import {JournalCheckpoint} from '../journal_checkpoint.mjs';

test('durable append checkpoint upgrades legacy state, reconciles interrupted commits and rejects acknowledged rollback', {skip:process.platform==='win32'},async()=>{
  const folder=await mkdtemp(join(tmpdir(),'warden-journal-'));const path=join(folder,'head');
  const dataset=randomUUID(),stamp=digest=>({dataset,revision:randomUUID(),digest:digest.repeat(64)});
  const a=stamp('a'),b=stamp('b'),c=stamp('c'),unknown=stamp('d');
  try{
    const old=new FileCheckpoint(path);await old.prepare(undefined,a);await old.finish(a);
    const journal=new JournalCheckpoint(path);await journal.verify(a);
    assert.equal((await stat(path+'.journal')).mode&0o777,0o600);
    await rename(path+'.legacy',path); // Crash after durable journal creation, before retirement.
    await new JournalCheckpoint(path).verify(a);
    await assert.rejects(stat(path));assert((await stat(path+'.legacy')).isFile());
    await journal.prepare(a,b);
    const interrupted=new JournalCheckpoint(path);await assert.rejects(interrupted.verify(unknown));
    await interrupted.verify(a); // Durable store never committed: abort intent.
    await interrupted.prepare(a,b);
    const committed=new JournalCheckpoint(path);await committed.verify(b); // Commit persisted before confirmation.
    await assert.rejects(new JournalCheckpoint(path).verify(a));
    await committed.prepare(b,c);await committed.finish(c);
    await new JournalCheckpoint(path).verify(c);
    await assert.rejects(new JournalCheckpoint(path).verify(b));
    // Compaction must retain the newest acknowledged state and its permissions.
    committed.bytes=8*1024*1024;
    const next=stamp('e');await committed.prepare(c,next);await committed.finish(next);
    await new JournalCheckpoint(path).verify(next);await assert.rejects(new JournalCheckpoint(path).verify(c));
    assert((await stat(path+'.journal')).size<4096);
    await rename(path+'.journal',path+'.journal.saved');
    await assert.rejects(new JournalCheckpoint(path).verify(a)); // No legacy fallback after upgrade.
  }finally{await rm(folder,{recursive:true,force:true});}
});

test('journal crash tails recover only known states; complete corruption and failed IO close access', {skip:process.platform==='win32'},async()=>{
  const folder=await mkdtemp(join(tmpdir(),'warden-journal-tail-'));const path=join(folder,'head');
  const a={dataset:randomUUID(),revision:randomUUID(),digest:'a'.repeat(64)},b={...a,revision:randomUUID(),digest:'b'.repeat(64)};
  try{
    const legacy=new FileCheckpoint(path);await legacy.prepare(undefined,a);await legacy.finish(a);
    const checkpoint=new JournalCheckpoint(path);await checkpoint.verify(a);
    const initial=await readFile(path+'.journal');
    await checkpoint.prepare(a,b);const prepared=await readFile(path+'.journal');
    await checkpoint.finish(b);const confirmed=await readFile(path+'.journal');
    await writeFile(path+'.journal',confirmed.subarray(0,confirmed.length-20)); // Torn confirmation.
    await new JournalCheckpoint(path).verify(b);await assert.rejects(new JournalCheckpoint(path).verify(a));
    await writeFile(path+'.journal',prepared.subarray(0,prepared.length-20)); // Torn intent cannot authorize new state.
    await assert.rejects(new JournalCheckpoint(path).verify(b));await new JournalCheckpoint(path).verify(a);
    await writeFile(path+'.journal',initial);await appendFile(path+'.journal','{"record":{},"checksum":"invalid"}\n');
    await assert.rejects(new JournalCheckpoint(path).verify(a));
    await writeFile(path+'.journal',initial);
    const failed=new JournalCheckpoint(path);await failed.verify(a);failed.path=join(folder,'missing','head');
    await assert.rejects(failed.prepare(a,b));failed.path=path+'.journal';
    await assert.rejects(failed.verify(a));await assert.rejects(failed.prepare(a,b));
    await new JournalCheckpoint(path).verify(a);
  }finally{await rm(folder,{recursive:true,force:true});}
});
