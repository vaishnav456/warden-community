import {test} from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {Box} from './box.mjs';
import {CipherDatabase} from '../engine.mjs';
import {MemoryCipherStore} from '../store.mjs';
import {MemoryCheckpoint} from '../checkpoint.mjs';
import {nativeFactory,verifyVolatileRoot} from '../native.mjs';
import {RestCompiler} from '../rest.mjs';

const enabled=process.env.WARDEN_NATIVE_TEST==='1';
const schema=`CREATE ROLE service_role;CREATE SCHEMA endpt;
  CREATE TABLE endpt.records(id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,name text UNIQUE NOT NULL,amount numeric(30,10));
  CREATE TABLE endpt.children(id integer PRIMARY KEY,parent_id bigint REFERENCES endpt.records DEFERRABLE INITIALLY DEFERRED);
  GRANT USAGE ON SCHEMA endpt TO service_role;GRANT SELECT,INSERT,UPDATE ON ALL TABLES IN SCHEMA endpt TO service_role;
  GRANT USAGE ON ALL SEQUENCES IN SCHEMA endpt TO service_role;`;
async function fixture(extraSchema=''){
  const store=new MemoryCipherStore(),box=new Box(),checkpoint=new MemoryCheckpoint(),dataset=randomUUID(),options={projection:nativeFactory()};
  const engine=await CipherDatabase.create(store,box,checkpoint,dataset,schema+extraSchema,[],[],options);
  return {engine,store,box,checkpoint,dataset,options};
}
const read=engine=>engine.application(tx=>tx.query('SELECT id::text,name,amount::text FROM endpt.records ORDER BY id'),{readOnly:true});
const deferred=()=>{let resolve;const promise=new Promise(r=>{resolve=r;});return {promise,resolve};};
async function completes(promise,message){
  let timer;
  try{return await Promise.race([promise,new Promise((_,reject)=>{timer=setTimeout(()=>reject(new Error(message)),3000);})]);}
  finally{clearTimeout(timer);}
}
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
test('native stable and immutable RPCs bypass pending durable writes while volatile RPCs wait',{skip:!enabled},async()=>{
  const f=await fixture(`
    CREATE FUNCTION endpt.record_count() RETURNS integer LANGUAGE sql STABLE AS $$
      SELECT count(*)::integer FROM endpt.records;
    $$;
    CREATE FUNCTION endpt.slow_count() RETURNS integer LANGUAGE plpgsql STABLE AS $$
      BEGIN PERFORM pg_sleep(0.2);RETURN (SELECT count(*)::integer FROM endpt.records);END;
    $$;
    CREATE FUNCTION endpt.constant() RETURNS integer LANGUAGE sql IMMUTABLE AS $$SELECT 7$$;
    CREATE FUNCTION endpt.append(p_name text) RETURNS integer LANGUAGE plpgsql VOLATILE AS $$
      BEGIN INSERT INTO endpt.records(name) VALUES(p_name);RETURN 1;END;
    $$;`);
  const compiler=new RestCompiler(f.engine),release=deferred(),entered=deferred();let write,volatile;
  const rpc=(name,data={})=>compiler.request({schema:'endpt',method:'POST',path:'rpc/'+name,data_json:JSON.stringify(data)});
  try{
    const commit=f.store.commit.bind(f.store);
    f.store.commit=async(...args)=>{entered.resolve();await release.promise;return commit(...args);};
    write=f.engine.execute("INSERT INTO endpt.records(name) VALUES('pending')");
    await entered.promise;
    // Exercise cold metadata lookup while the durable writer is blocked.
    assert.equal((await completes(rpc('record_count'),'cold stable RPC waited for durability')).body,'0');
    let acknowledged=false;
    volatile=rpc('append',{p_name:'after'}).then(result=>{acknowledged=true;return result;});
    const started=performance.now();
    const results=await completes(Promise.all(Array.from({length:8},()=>rpc('slow_count'))),'stable RPCs waited for durability');
    assert(performance.now()-started<1200,'stable RPCs serialized or waited for durability');
    assert(results.every(result=>result.body==='0'),'RPC observed an undurable row');
    assert.equal((await completes(rpc('constant'),'immutable RPC waited for durability')).body,'7');assert.equal(acknowledged,false);
    release.resolve();await write;assert.equal((await volatile).body,'1');
    assert.equal((await rpc('record_count')).body,'2');
    await f.engine.close();f.engine=await CipherDatabase.open(f.store,f.box,f.checkpoint,f.dataset,f.options);
    assert.deepEqual((await read(f.engine)).rows.map(row=>row.name),['pending','after']);
  }finally{release.resolve();await Promise.allSettled([write,volatile]);await f.engine.close();}
});
test('native catalog-classified read-only RPCs reject writes and sequence changes',{skip:!enabled},async()=>{
  const f=await fixture(`
    CREATE FUNCTION endpt.bad_stable() RETURNS integer LANGUAGE plpgsql STABLE AS $$
      BEGIN INSERT INTO endpt.records(name) VALUES('forbidden');RETURN 1;END;
    $$;
    CREATE FUNCTION endpt.bad_immutable() RETURNS bigint LANGUAGE sql IMMUTABLE AS $$
      SELECT nextval('endpt.records_id_seq');
    $$;`);
  const compiler=new RestCompiler(f.engine);
  try{
    const revision=f.engine.state.revision;
    for(const name of ['bad_stable','bad_immutable'])await assert.rejects(
      compiler.request({schema:'endpt',method:'POST',path:'rpc/'+name,data_json:'{}'}));
    assert.equal((await read(f.engine)).rows.length,0);assert.equal(f.engine.state.revision,revision);
    assert.equal((await f.engine.execute("INSERT INTO endpt.records(name) VALUES('allowed') RETURNING id::text")).rows[0].id,'1');
  }finally{await f.engine.close();}
});
test('native application batches acknowledge one durable commit and roll back every operation on failure',{skip:!enabled},async()=>{
  const f=await fixture(`CREATE FUNCTION endpt.append(p_name text) RETURNS SETOF endpt.records LANGUAGE plpgsql AS $$
    BEGIN RETURN QUERY INSERT INTO endpt.records(name) VALUES(p_name) RETURNING *;END;$$;`);
  let compiler=new RestCompiler(f.engine),batch;
  const release=deferred(),entered=deferred(),commit=f.store.commit.bind(f.store);let commits=0,acknowledged=false;
  const operation=(path,method,data)=>({schema:'endpt',path,method,data_json:JSON.stringify(data),prefer:'return=representation'});
  try{
    f.store.commit=async(...args)=>{commits++;entered.resolve();await release.promise;return commit(...args);};
    batch=compiler.requestBatch([
      {schema:'endpt',path:'records',method:'POST',prefer:'return=representation',data_json:'{"name":"one","amount":12345678901234567890.1234567890}'},
      operation('children','POST',{id:1,parent_id:1}),
      operation('rpc/append','POST',{p_name:'two'}),
    ]).then(result=>{acknowledged=true;return result;});
    await entered.promise;
    assert.equal((await read(f.engine)).rows.length,0);assert.equal(acknowledged,false);
    release.resolve();const results=await batch;
    assert.deepEqual(results.map(result=>result.status),[201,201,200]);assert.equal(commits,1);
    assert(results[0].body.includes('12345678901234567890.1234567890'));
    f.store.commit=async(...args)=>{commits++;return commit(...args);};
    const revision=f.engine.state.revision;
    await assert.rejects(compiler.requestBatch([
      operation('records?id=eq.1','PATCH',{name:'rollback'}),
      operation('children','POST',{id:2,parent_id:999}),
    ]));
    assert.equal(commits,1);assert.equal(f.engine.state.revision,revision);assert.equal((await read(f.engine)).rows[0].name,'one');
    await assert.rejects(compiler.requestBatch([
      operation('records?id=eq.1','PATCH',{name:'rollback'}),
      operation('rpc/missing','POST',{}),
    ]),error=>error.code==='PGRST202'&&error.status===404);
    assert.equal(commits,1);assert.equal((await read(f.engine)).rows[0].name,'one');
    await assert.rejects(compiler.requestBatch([
      operation('records','POST',{name:'discarded'}),
      operation('rpc/append','POST',{p_name:'one'}),
    ]));
    assert.equal(commits,1);
    const next=await compiler.requestBatch([operation('records','POST',{name:'three'})]);
    assert.equal(JSON.parse(next[0].body)[0].id,3,'rejected batch advanced sequence');assert.equal(commits,2);
    // Storage failures also reject the entire batch and restore readable state.
    f.store.commit=async()=>{throw new Error('injected durability failure');};
    await assert.rejects(compiler.requestBatch([
      operation('records?id=eq.1','PATCH',{name:'not durable'}),
      operation('children','POST',{id:3,parent_id:3}),
    ]));
    assert.equal((await read(f.engine)).rows[0].name,'one');
    f.store.commit=commit;await f.engine.close();f.engine=await CipherDatabase.open(f.store,f.box,f.checkpoint,f.dataset,f.options);
    compiler=new RestCompiler(f.engine);
    assert.deepEqual((await read(f.engine)).rows.map(row=>row.name),['one','two','three']);
    assert.equal(JSON.parse((await compiler.request({schema:'endpt',path:'children',method:'GET'})).body).length,1);
  }finally{release.resolve();await Promise.allSettled([batch]);await f.engine.close();}
});
test('native atomic login uses the shipped session routine, retains session limits and recovers bookkeeping',{skip:!enabled},async()=>{
  const source=await readFile(new URL('../../db-init/02-schema.sql',import.meta.url),'utf8');
  const tables=['admin_users','refresh_tokens'].map(name=>{
    const definition=source.match(new RegExp('CREATE TABLE endpt\\.'+name+' \\([\\s\\S]*?\\n\\);'))?.[0];
    assert(definition,'missing shipped session table '+name);return definition;
  });
  const routine=source.match(/CREATE OR REPLACE FUNCTION endpt\.create_refresh_session\([\s\S]*?\n\$\$;/)?.[0];
  assert(routine,'missing shipped create_refresh_session routine');
  const permissions=source.split('\n').filter(line=>/^(REVOKE ALL|GRANT EXECUTE) ON FUNCTION endpt\.create_refresh_session\(/.test(line)).join('\n');
  assert(permissions.includes('FROM PUBLIC')&&permissions.includes('TO service_role'),'missing shipped routine permissions');
  const f=await fixture(`CREATE TABLE endpt.companies(id uuid PRIMARY KEY);
    CREATE TABLE endpt.branches(id uuid PRIMARY KEY);
    ${tables.join('\n')}
    ${routine}
    ${permissions}
    GRANT SELECT,INSERT,UPDATE ON ALL TABLES IN SCHEMA endpt TO service_role;`);
  const admin=randomUUID(),expires=new Date(Date.now()+3600000).toISOString(),absolute=new Date(Date.now()+7200000).toISOString();
  let compiler=new RestCompiler(f.engine),commits=0;
  const operation=(path,method,data,prefer='return=representation')=>({schema:'endpt',path,method,data_json:JSON.stringify(data),prefer});
  const session=hash=>operation('rpc/create_refresh_session','POST',{
    p_admin_id:admin,p_token_hash:hash,p_ip_address:'192.0.2.2',p_user_agent:'synthetic-agent-'.repeat(50),
    p_expires_at:expires,p_absolute_expires_at:absolute,p_max_sessions:1,
  });
  const bookkeeping=operation('admin_users?id=eq.'+admin,'PATCH',{
    last_login_at:new Date().toISOString(),last_login_ip:'192.0.2.2',failed_attempts:0,locked_until:null,
  },'return=minimal');
  const currentAdmin=async()=>JSON.parse((await compiler.request(operation('admin_users?id=eq.'+admin,'GET'))).body)[0];
  const currentSessions=async()=>JSON.parse((await compiler.request(operation('refresh_tokens?order=token_hash.asc','GET'))).body);
  try{
    await compiler.request(operation('admin_users','POST',{
      id:admin,email:'synthetic-login@example.invalid',password_hash:'synthetic hash',full_name:'Synthetic admin',role:'technician',
      failed_attempts:4,locked_until:'2000-01-02T00:00:00Z',last_login_at:'2000-01-01T00:00:00Z',last_login_ip:'192.0.2.1',
    }));
    const old=JSON.parse((await compiler.request(session('existing-hash'))).body)[0];
    await compiler.request(operation('refresh_tokens?id=eq.'+old.id,'PATCH',{
      created_at:'2000-01-01T00:00:00Z',last_used_at:'2000-01-01T00:00:00Z',
    }));
    const before=await currentAdmin(),revision=f.engine.state.revision,commit=f.store.commit.bind(f.store);
    f.store.commit=async(...args)=>{commits++;return commit(...args);};
    // The real routine rejects a duplicate hash after the admin PATCH ran.
    // Both bookkeeping and session revocation must remain unchanged.
    await assert.rejects(compiler.requestBatch([bookkeeping,session('existing-hash')]),error=>error.code==='23505');
    assert.deepEqual(await currentAdmin(),before);assert.equal(f.engine.state.revision,revision);assert.equal(commits,0);
    assert.equal((await currentSessions()).length,1);assert.equal((await currentSessions())[0].revoked,false);
    const results=await compiler.requestBatch([bookkeeping,session('new-hash')]);
    assert.deepEqual(results.map(result=>result.status),[200,200]);assert.equal(results[0].body,'');assert.equal(commits,1);
    const created=JSON.parse(results[1].body)[0];assert.equal(created.token_hash,'new-hash');assert.equal(created.user_agent.length,500);
    const loggedIn=await currentAdmin();assert.equal(loggedIn.failed_attempts,0);assert.equal(loggedIn.locked_until,null);
    assert.equal(loggedIn.last_login_ip,'192.0.2.2');assert.notEqual(loggedIn.last_login_at,before.last_login_at);
    const tokens=await currentSessions();assert.equal(tokens.length,2);
    assert.equal(tokens.filter(token=>!token.revoked).length,1);
    assert.equal(tokens.find(token=>token.token_hash==='new-hash').revoked,false);
    assert.equal(tokens.find(token=>token.token_hash==='existing-hash').revoked,true);
    assert(tokens.find(token=>token.token_hash==='existing-hash').revoked_at);
    await f.engine.close();f.engine=await CipherDatabase.open(f.store,f.box,f.checkpoint,f.dataset,f.options);
    compiler=new RestCompiler(f.engine);
    assert.deepEqual(await currentAdmin(),loggedIn);assert.deepEqual(await currentSessions(),tokens);
  }finally{await f.engine.close();}
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
