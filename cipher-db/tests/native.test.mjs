import {test} from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {Box} from './box.mjs';
import {CipherDatabase} from '../engine.mjs';
import {MemoryCipherStore} from '../store.mjs';
import {MemoryCheckpoint} from '../checkpoint.mjs';
import {nativeFactory,verifyVolatileRoot} from '../native.mjs';

const enabled=process.env.WARDEN_NATIVE_TEST==='1';
const schema=`CREATE ROLE service_role;CREATE SCHEMA endpt;
  CREATE TABLE endpt.records(id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,name text UNIQUE NOT NULL,amount numeric(30,10));
  CREATE TABLE endpt.children(id integer PRIMARY KEY,parent_id bigint REFERENCES endpt.records DEFERRABLE INITIALLY DEFERRED);
  GRANT USAGE ON SCHEMA endpt TO service_role;GRANT SELECT,INSERT,UPDATE ON ALL TABLES IN SCHEMA endpt TO service_role;
  GRANT USAGE ON ALL SEQUENCES IN SCHEMA endpt TO service_role;`;
async function fixture(){
  const store=new MemoryCipherStore(),box=new Box(),checkpoint=new MemoryCheckpoint(),dataset=randomUUID(),options={projection:nativeFactory()};
  const engine=await CipherDatabase.create(store,box,checkpoint,dataset,schema,[],[],options);
  return {engine,store,box,checkpoint,dataset,options};
}
const read=engine=>engine.application(tx=>tx.query('SELECT id::text,name,amount::text FROM endpt.records ORDER BY id'),{readOnly:true});
const deferred=()=>{let resolve;const promise=new Promise(r=>{resolve=r;});return {promise,resolve};};
test('native projection rejects persistent filesystems',{skip:!enabled},async()=>{
  await assert.rejects(verifyVolatileRoot('/app'),/tmpfs/);
});
test('native readers run concurrently and do not wait for or observe undurable writes',{skip:!enabled},async()=>{
  const f=await fixture(),release=deferred();
  try{
    const locale=(await f.engine.transaction(tx=>tx.query("SELECT datcollate,datctype FROM pg_database WHERE datname=current_database()"),{readOnly:true})).rows[0];
    assert.deepEqual(locale,{datcollate:'C',datctype:'C.UTF-8'});
    const commit=f.store.commit.bind(f.store),entered=deferred();let acknowledged=false;
    f.store.commit=async(...args)=>{entered.resolve();await release.promise;return commit(...args);};
    const write=f.engine.execute("INSERT INTO endpt.records(name,amount) VALUES('pending',12345678901234567890.1234567890)").then(()=>{acknowledged=true;});
    await entered.promise;
    const started=performance.now();
    const results=await Promise.all(Array.from({length:8},()=>f.engine.application(async tx=>{
      await tx.query('SELECT pg_sleep(0.2)');return tx.query('SELECT count(*)::int AS n FROM endpt.records');
    },{readOnly:true})));
    assert(performance.now()-started<1200,'readers serialized');
    assert(results.every(result=>result.rows[0].n===0));assert.equal(acknowledged,false);
    release.resolve();await write;f.store.commit=commit;
    assert.equal((await read(f.engine)).rows[0].amount,'12345678901234567890.1234567890');
    await assert.rejects(f.engine.application(tx=>tx.query("SELECT nextval('endpt.records_id_seq')"),{readOnly:true}));
    await assert.rejects(f.engine.application(tx=>tx.query('SELECT * FROM _warden_private_runtime.journal'),{readOnly:true}));
    await f.engine.close();f.engine=await CipherDatabase.open(f.store,f.box,f.checkpoint,f.dataset,f.options);
    assert.equal((await read(f.engine)).rows[0].name,'pending');
  }finally{release.resolve();await f.engine.close();}
});
test('native group commits isolate failed requests, constraints and counters and acknowledge only durable batches',{skip:!enabled},async()=>{
  const f=await fixture();let commits=0;
  try{
    const commit=f.store.commit.bind(f.store);f.store.commit=async(...args)=>{commits++;return commit(...args);};
    const results=await Promise.allSettled([
      f.engine.execute("INSERT INTO endpt.records(name) VALUES('one') RETURNING id::text"),
      f.engine.execute("INSERT INTO endpt.records(name) VALUES('one') RETURNING id::text"),
      f.engine.execute('INSERT INTO endpt.children VALUES(1,999)'),
      f.engine.transaction(async tx=>{await tx.query('INSERT INTO endpt.children VALUES(2,2)');return tx.query("INSERT INTO endpt.records(name) VALUES('two') RETURNING id::text");}),
    ]);
    assert.equal(commits,1);assert.deepEqual(results.map(r=>r.status),['fulfilled','rejected','rejected','fulfilled']);
    assert.equal(results[3].value.rows[0].id,'2');
    assert.equal((await f.engine.transaction(tx=>tx.query('SELECT count(*)::int AS n FROM endpt.children'),{readOnly:true})).rows[0].n,1);
    f.store.commit=async()=>{throw new Error('injected durable failure');};
    const failed=await Promise.allSettled(['three','four'].map(name=>f.engine.execute('INSERT INTO endpt.records(name) VALUES($1)',[name])));
    assert(failed.every(result=>result.status==='rejected'));assert.equal((await read(f.engine)).rows.length,2);
    f.store.commit=commit;await f.engine.close();f.engine=await CipherDatabase.open(f.store,f.box,f.checkpoint,f.dataset,f.options);
    assert.deepEqual((await read(f.engine)).rows.map(row=>row.name),['one','two']);
  }finally{await f.engine.close();}
});
test('native checkpoint interruption rebuilds authoritative ciphertext before further reads',{skip:!enabled},async()=>{
  const f=await fixture();
  try{
    const finish=f.checkpoint.finish.bind(f.checkpoint);let once=true;
    f.checkpoint.finish=async stamp=>{if(once){once=false;throw new Error('injected');}return finish(stamp);};
    await assert.rejects(f.engine.execute("INSERT INTO endpt.records(name) VALUES('durable')"));
    assert.equal((await read(f.engine)).rows[0].name,'durable');
    const old=await f.store.read();await f.engine.execute("INSERT INTO endpt.records(name) VALUES('newer')");
    f.store.state=old;await assert.rejects(read(f.engine));assert.equal(f.engine.closed,true);
  }finally{await f.engine.close();}
});
