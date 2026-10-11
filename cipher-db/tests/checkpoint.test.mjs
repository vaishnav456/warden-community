import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,writeFile,readFile,stat,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {randomUUID} from 'node:crypto';
import {FileCheckpoint,MemoryCheckpoint,stamp} from '../checkpoint.mjs';
test('prepared checkpoint recovers exactly old or committed revisions and rejects a third state',async()=>{
  const cp=new MemoryCheckpoint(),dataset=randomUUID(),before=stamp(dataset,{revision:randomUUID(),manifest:'old'}),after=stamp(dataset,{revision:randomUUID(),manifest:'new'});
  await cp.prepare(undefined,before);await cp.finish(before);
  await cp.prepare(before,after);await cp.verify(before);assert.equal(cp.pending,null);
  await cp.prepare(before,after);await cp.verify(after);assert.deepEqual(cp.head,after);
  await cp.prepare(after,before);await assert.rejects(cp.verify(stamp(dataset,{revision:randomUUID(),manifest:'third'})));
});
test('Linux checkpoint writes survive new instances, interrupted commits and restrictive permissions',{skip:process.platform!=='linux'},async()=>{
  const directory=await mkdtemp(join(tmpdir(),'warden-cipher-checkpoint-')),path=join(directory,'head'),dataset=randomUUID();
  const before=stamp(dataset,{revision:randomUUID(),manifest:'old'}),after=stamp(dataset,{revision:randomUUID(),manifest:'new'});
  try{
    const cp=new FileCheckpoint(path);await cp.prepare(undefined,before);await cp.finish(before);
    assert.equal((await stat(path)).mode&0o777,0o600);
    await cp.prepare(before,after);await new FileCheckpoint(path).verify(after);
    assert.deepEqual(JSON.parse(await readFile(path,'utf8')),after);
    await cp.prepare(after,before);await new FileCheckpoint(path).verify(after);
    await assert.rejects(new FileCheckpoint(path).verify(before));
    await writeFile(path+'.pending',JSON.stringify({before:after,after:before}),{mode:0o600});
    await assert.rejects(new FileCheckpoint(path).verify(stamp(dataset,{revision:randomUUID(),manifest:'tampered'})));
  }finally{await rm(directory,{recursive:true,force:true});}
});
