import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID, randomBytes, createCipheriv, createDecipheriv } from 'node:crypto';
import { CipherDatabase } from '../engine.mjs';
import { MemoryCipherStore } from '../store.mjs';
import { MemoryCheckpoint,FileCheckpoint } from '../checkpoint.mjs';
import {JournalCheckpoint} from '../journal_checkpoint.mjs';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import { sealDocument, unsealDocument } from '../crypto.mjs';

// Keys are generated for synthetic tests only; the production adapter never
// obtains key material from the key custody service.
class TestBox {
  key=randomBytes(32);
  async seal(id,purpose,value) {
    const nonce=randomBytes(12), cipher=createCipheriv('aes-256-gcm',this.key,nonce);
    cipher.setAAD(Buffer.from(JSON.stringify([purpose,id])));
    const data=Buffer.concat([cipher.update(value,'utf8'),cipher.final()]);
    return 'enc:v1:'+Buffer.concat([nonce,cipher.getAuthTag(),data]).toString('base64url');
  }
  async unseal(id,purpose,value) {
    const data=Buffer.from(value.slice(7),'base64url'), cipher=createDecipheriv('aes-256-gcm',this.key,data.subarray(0,12));
    cipher.setAAD(Buffer.from(JSON.stringify([purpose,id]))); cipher.setAuthTag(data.subarray(12,28));
    return Buffer.concat([cipher.update(data.subarray(28)),cipher.final()]).toString('utf8');
  }
}
const schema=`CREATE SCHEMA endpt;
CREATE TABLE endpt.parents(id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, name text NOT NULL UNIQUE);
CREATE TABLE endpt.children(parent_id bigint REFERENCES endpt.parents ON DELETE CASCADE, code text,
 amount numeric(30,10), tags text[], extra jsonb, PRIMARY KEY(parent_id,code));
CREATE TABLE endpt.empty_records(id uuid PRIMARY KEY);
CREATE FUNCTION endpt.claim(p_name text) RETURNS SETOF endpt.parents LANGUAGE plpgsql AS $$
BEGIN RETURN QUERY INSERT INTO endpt.parents(name) VALUES(p_name) ON CONFLICT(name) DO NOTHING RETURNING *; END $$;`;
async function fixture(customSchema=schema) {
  const store=new MemoryCipherStore(),box=new TestBox(),checkpoint=new MemoryCheckpoint(),dataset=randomUUID();
  const engine=await CipherDatabase.create(store,box,checkpoint,dataset,customSchema);
  return {store,box,checkpoint,dataset,engine};
}
test('runtime upgrades a legacy checkpoint, durably writes with the journal and rejects database rollback after restart',{skip:process.platform!=='linux'},async()=>{
  const folder=await mkdtemp(join(tmpdir(),'warden-runtime-journal-')),path=join(folder,'head');
  const store=new MemoryCipherStore(),box=new TestBox(),dataset=randomUUID();let engine;
  try{
    engine=await CipherDatabase.create(store,box,new FileCheckpoint(path),dataset,schema);
    const initial=await store.read();await engine.close();
    engine=await CipherDatabase.open(store,box,new JournalCheckpoint(path),dataset);
    await engine.execute('INSERT INTO endpt.parents(name) VALUES($1)',['journal fixture']);await engine.close();
    engine=await CipherDatabase.open(store,box,new JournalCheckpoint(path),dataset);
    assert.equal((await engine.execute('SELECT count(*)::int AS n FROM endpt.parents')).rows[0].n,1);
    await engine.close();store.state=initial;
    await assert.rejects(CipherDatabase.open(store,box,new JournalCheckpoint(path),dataset));
  }finally{await engine?.close();await rm(folder,{recursive:true,force:true});}
});
test('complete records, including empty tables, persist only as ciphertext and recover exact types',async()=>{
  const f=await fixture();
  try {
    await f.engine.execute("INSERT INTO endpt.parents(name) VALUES($1)",['Private company']);
    await f.engine.execute("INSERT INTO endpt.children VALUES(1,'秘密',12345678901234567890.1234567890,ARRAY['a,b','x'],NULL)");
    const stored=await f.store.read();
    assert.equal(stored.collections.size,3);
    const text=JSON.stringify([...stored.collections].map(([id,rows])=>[id,[...rows]]))+stored.manifest;
    for(const clear of ['Private company','秘密','12345678901234567890','parents','children','endpt']) assert(!text.includes(clear));
    for(const rows of stored.collections.values()) for(const payload of rows.values()) assert(payload.startsWith('wdb1:'));
    await f.engine.close();
    f.engine=await CipherDatabase.open(f.store,f.box,f.checkpoint,f.dataset);
    const row=(await f.engine.execute('SELECT amount::text,tags,extra FROM endpt.children')).rows[0];
    assert.equal(row.amount,'12345678901234567890.1234567890'); assert.deepEqual(row.tags,['a,b','x']); assert.equal(row.extra,null);
    const next=(await f.engine.execute("INSERT INTO endpt.parents(name) VALUES('Next') RETURNING id::text")).rows[0];
    assert.equal(next.id,'2');
  } finally {await f.engine.close();}
});
test('atomic routines, concurrent callers, cascades and failed transactions survive restart',async()=>{
  const f=await fixture();
  try {
    const results=await Promise.all(Array.from({length:5},()=>f.engine.execute('SELECT * FROM endpt.claim($1)',['unique'])));
    assert.equal(results.reduce((n,r)=>n+r.rows.length,0),1);
    await f.engine.execute("INSERT INTO endpt.children VALUES(1,'child',1,NULL,NULL)");
    await assert.rejects(f.engine.execute("INSERT INTO endpt.children VALUES(999,'bad',1,NULL,NULL)"));
    assert.equal((await f.engine.execute('SELECT count(*)::int AS n FROM endpt.children')).rows[0].n,1);
    await f.engine.execute('DELETE FROM endpt.parents WHERE id=1');
    await f.engine.close(); f.engine=await CipherDatabase.open(f.store,f.box,f.checkpoint,f.dataset);
    assert.equal((await f.engine.execute('SELECT count(*)::int AS n FROM endpt.children')).rows[0].n,0);
  } finally {await f.engine.close();}
});
test('deferred constraints reject invalid transactions before persistence and allow valid multi-statement transactions',async()=>{
  const f=await fixture(schema.replace('ON DELETE CASCADE','ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED'));
  try {
    const revision=(await f.store.head()).revision;
    await assert.rejects(f.engine.execute("INSERT INTO endpt.children VALUES(100,'invalid',1,NULL,NULL)"));
    assert.equal((await f.store.head()).revision,revision);
    assert.equal((await f.engine.execute('SELECT count(*)::int AS n FROM endpt.children')).rows[0].n,0);
    await f.engine.transaction(async tx=>{
      await tx.query("INSERT INTO endpt.children VALUES(100,'valid',1,NULL,NULL)");
      await tx.query("INSERT INTO endpt.parents(id,name) OVERRIDING SYSTEM VALUE VALUES(100,'created later')");
    });
    await f.engine.close();f.engine=await CipherDatabase.open(f.store,f.box,f.checkpoint,f.dataset);
    assert.equal((await f.engine.execute('SELECT count(*)::int AS n FROM endpt.children c JOIN endpt.parents p ON p.id=c.parent_id')).rows[0].n,1);
  } finally {await f.engine.close();}
});
test('missing or modified ciphertext, cross-record substitution and database rollback fail closed',async()=>{
  const f=await fixture();
  await f.engine.execute("INSERT INTO endpt.parents(name) VALUES('one')");
  const earlier=await f.store.read();
  await f.engine.execute("INSERT INTO endpt.parents(name) VALUES('two')");
  const good=await f.store.read(); await f.engine.close();
  for(const mode of ['remove','alter','swap','rollback']) {
    f.store.state=structuredClone(good);
    const rows=[...f.store.state.collections.values()].find(rows=>rows.size===2);
    const [first,second]=[...rows];
    if(mode==='remove') rows.delete(first[0]);
    if(mode==='alter') rows.set(first[0],second[1]);
    if(mode==='swap') {rows.set(first[0],second[1]);rows.set(second[0],first[1]);}
    if(mode==='rollback') f.store.state=structuredClone(earlier);
    await assert.rejects(CipherDatabase.open(f.store,f.box,f.checkpoint,f.dataset));
  }
});
test('chunked unicode record authenticates identity, purpose and order',async()=>{
  const box=new TestBox(),text='🛡'.repeat(400000),id=randomUUID();
  const payload=await sealDocument(box,id,'test',text);
  assert.equal(await unsealDocument(box,id,'test',payload),text);
  await assert.rejects(unsealDocument(box,randomUUID(),'test',payload));
  await assert.rejects(unsealDocument(box,id,'other',payload));
  const parts=JSON.parse(Buffer.from(payload.slice(5),'base64url'));parts.reverse();
  await assert.rejects(unsealDocument(box,id,'test','wdb1:'+Buffer.from(JSON.stringify(parts)).toString('base64url')));
});
test('cold commit failure leaves no acknowledged or restored partial write',async()=>{
  const f=await fixture();
  const commit=f.store.commit.bind(f.store); f.store.commit=async()=>{throw new Error('injected');};
  await assert.rejects(f.engine.execute("INSERT INTO endpt.parents(name) VALUES('lost')"));
  f.store.commit=commit;
  assert.equal((await f.engine.execute('SELECT count(*)::int AS n FROM endpt.parents')).rows[0].n,0);
  await f.engine.execute("INSERT INTO endpt.parents(name) VALUES('saved')");
  await f.engine.close(); f.engine=await CipherDatabase.open(f.store,f.box,f.checkpoint,f.dataset);
  assert.equal((await f.engine.execute('SELECT name FROM endpt.parents')).rows[0].name,'saved');
  await f.engine.close();
});
test('post-commit checkpoint interruption recovers durable data before another query',async()=>{
  const f=await fixture(),finish=f.checkpoint.finish.bind(f.checkpoint);let once=true;
  f.checkpoint.finish=async value=>{if(once){once=false;throw new Error('injected checkpoint interruption');}return finish(value);};
  try{
    await assert.rejects(f.engine.execute("INSERT INTO endpt.parents(name) VALUES('durable')"));
    assert.equal((await f.engine.execute('SELECT name FROM endpt.parents')).rows[0].name,'durable');
    await f.engine.close();f.engine=await CipherDatabase.open(f.store,f.box,f.checkpoint,f.dataset);
    assert.equal((await f.engine.execute('SELECT name FROM endpt.parents')).rows[0].name,'durable');
  }finally{await f.engine.close();}
});
test('sequence-only changes persist and storage tampering during a running session closes access',async()=>{
  const f=await fixture();
  await f.engine.execute("SELECT nextval('endpt.parents_id_seq')");await f.engine.close();
  f.engine=await CipherDatabase.open(f.store,f.box,f.checkpoint,f.dataset);
  assert.equal((await f.engine.execute("INSERT INTO endpt.parents(name) VALUES('next') RETURNING id::text")).rows[0].id,'2');
  [...f.store.state.collections.values()].find(rows=>rows.size).clear();
  await assert.rejects(f.engine.audit());await assert.rejects(f.engine.execute('SELECT 1'));
  await f.engine.close();
});
test('read-only transactions preserve revision and reject writes and sequence changes',async()=>{
  const f=await fixture();
  try{
    const revision=(await f.store.head()).revision;
    assert.equal((await f.engine.transaction(tx=>tx.query('SELECT count(*)::int AS n FROM endpt.parents'),{readOnly:true})).rows[0].n,0);
    await assert.rejects(f.engine.transaction(tx=>tx.query("INSERT INTO endpt.parents(name) VALUES('blocked')"),{readOnly:true}));
    await assert.rejects(f.engine.transaction(tx=>tx.query("SELECT nextval('endpt.parents_id_seq')"),{readOnly:true}));
    assert.equal((await f.store.head()).revision,revision);
    assert.equal((await f.engine.execute("INSERT INTO endpt.parents(name) VALUES('first') RETURNING id::text")).rows[0].id,'1');
  }finally{await f.engine.close();}
});
test('application role retains audit immutability and cannot access the private journal',async()=>{
  const store=new MemoryCipherStore(),box=new TestBox(),checkpoint=new MemoryCheckpoint(),dataset=randomUUID();
  const engine=await CipherDatabase.create(store,box,checkpoint,dataset,`CREATE ROLE service_role;
    CREATE SCHEMA endpt;CREATE TABLE endpt.audit_log(id integer PRIMARY KEY,detail text);
    GRANT USAGE ON SCHEMA endpt TO service_role;GRANT SELECT,INSERT ON endpt.audit_log TO service_role;`);
  try{
    await engine.application(tx=>tx.query("INSERT INTO endpt.audit_log VALUES(1,'audit')"));
    await assert.rejects(engine.application(tx=>tx.query('DELETE FROM endpt.audit_log')));
    await assert.rejects(engine.application(tx=>tx.query('SELECT * FROM _warden_private_runtime.journal')));
    assert.equal((await engine.application(tx=>tx.query('SELECT count(*)::int AS n FROM endpt.audit_log'))).rows[0].n,1);
  }finally{await engine.close();}
});
