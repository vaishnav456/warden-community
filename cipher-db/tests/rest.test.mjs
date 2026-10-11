import {test} from 'node:test';
import assert from 'node:assert/strict';
import {PGlite} from '@electric-sql/pglite';
import {RestCompiler} from '../rest.mjs';
import {nativeFactory} from '../native.mjs';
for(const native of [false,true])test(`${native?'native':'memory'} query compatibility: joins, inner filters, pagination, atomic routines and exact JSON numbers`,{skip:native&&process.env.WARDEN_NATIVE_TEST!=='1'},async()=>{
  const schema=`CREATE SCHEMA endpt;
  CREATE TABLE endpt.companies(id bigint PRIMARY KEY,name text,active boolean);
  CREATE TABLE endpt.endpoints(id integer PRIMARY KEY,company_id bigint REFERENCES endpt.companies,name text,tags text[]);
  CREATE FUNCTION endpt.bump(p_id bigint,p_name text DEFAULT 'default') RETURNS jsonb LANGUAGE plpgsql AS $$
    BEGIN UPDATE endpt.companies SET name=p_name WHERE id=p_id;RETURN jsonb_build_object('ok',FOUND);END $$;
  CREATE FUNCTION endpt.no_args() RETURNS integer LANGUAGE sql AS $$SELECT 7$$;
  CREATE FUNCTION endpt.stable_count() RETURNS integer LANGUAGE sql STABLE AS $$SELECT count(*)::int FROM endpt.companies$$;
  CREATE FUNCTION endpt.immutable_value(p_value integer DEFAULT 9) RETURNS integer LANGUAGE sql IMMUTABLE AS $$SELECT p_value$$;
  CREATE FUNCTION endpt.ambiguous(p_value integer) RETURNS integer LANGUAGE sql AS $$SELECT p_value$$;
  CREATE FUNCTION endpt.ambiguous(p_value text) RETURNS text LANGUAGE sql AS $$SELECT p_value$$;`;
  const db=native?await nativeFactory()(schema):new PGlite();if(!native)await db.exec(schema);
  const applications=[];
  const compiler=new RestCompiler({application:(fn,options)=>{applications.push(options);return db.transaction(fn,options);}});
  const request=(path,method='GET',data_json,prefer)=>compiler.request({schema:'endpt',path,method,data_json,prefer});
  try {
    await request('companies','POST','[{"id":9007199254740993,"name":"Alice","active":true},{"id":2,"name":"Bob","active":false}]');
    await request('endpoints','POST','[{"id":1,"company_id":9007199254740993,"name":"Laptop","tags":["one"]},{"id":2,"company_id":2,"name":"Desktop","tags":null}]');
    const joined=await request('companies?select=id,name,endpoints!inner(id,name)&endpoints.name=eq.Laptop&order=id.desc&limit=1&offset=0','GET',undefined,'count=exact');
    assert(joined.body.includes('9007199254740993'));assert.equal(joined.headers['Content-Range'],'0-0/1');assert.equal(JSON.parse(joined.body)[0].endpoints[0].name,'Laptop');
    const forward=JSON.parse((await request('endpoints?select=id,companies(name)&id=eq.1')).body);
    assert.equal(forward[0].companies.name,'Alice');
    await request('endpoints?id=eq.1','PATCH','{"tags":["changed","x"],"name":"Changed"}');
    assert.deepEqual(JSON.parse((await request('endpoints?id=eq.1')).body)[0].tags,['changed','x']);
    const routine=await request('rpc/bump','POST','{"p_id":9007199254740993,"p_name":"Routine"}');assert.deepEqual(JSON.parse(routine.body),{ok:true});assert.equal(applications.at(-1).readOnly,false);
    await assert.rejects(request('rpc/missing','POST','{}'),error=>error.code==='PGRST202'&&error.status===404);
    await assert.rejects(request('rpc/ambiguous','POST','{"p_value":1}'),error=>error.code==='PGRST202'&&error.status===404);
    await assert.rejects(request('rpc/stable_count','POST','{"unknown":1}'),error=>error.code==='PGRST202'&&error.status===404);
    assert.equal((await request('rpc/no_args','POST','{}')).body,'7');assert.equal(applications.at(-1).readOnly,false);
    assert.equal((await request('rpc/stable_count','POST','{}')).body,'2');assert.equal(applications.at(-1).readOnly,true);
    assert.equal((await request('rpc/immutable_value','POST','{}')).body,'9');assert.equal(applications.at(-1).readOnly,true);
    assert.equal((await compiler.request({schema:'endpt',path:'rpc/bump',method:'POST',data_json:'{"p_id":2}',readOnly:true})).status,200);
    assert.equal(applications.at(-1).readOnly,false,'caller readOnly flag cannot change volatility');
    assert.equal(JSON.parse((await request('companies?id=eq.9007199254740993')).body)[0].name,'Routine');
    const logical=await request('companies?or=(active.eq.false,name.eq.Routine)&id=not.in.(3,4)');assert.equal(JSON.parse(logical.body).length,2);
    assert.equal((await request('companies?active=eq.true','HEAD')).headers['Content-Range'],'*/1');
    await request('endpoints?on_conflict=id','POST','{"id":1,"name":"Upsert","company_id":2,"tags":null}','resolution=merge-duplicates,return=representation');
    assert.equal(JSON.parse((await request('endpoints?id=eq.1')).body)[0].name,'Upsert');
    await assert.rejects(request('companies?id=eq.2;DROP TABLE endpt.companies')); // value cannot execute SQL
    await assert.rejects(request('companies','DELETE'));
    assert.equal(JSON.parse((await request('companies')).body).length,2);
  } finally {await db.close();}
});
test('application batches reject invalid counts and operation envelopes before execution',async()=>{
  let applications=0;
  const compiler=new RestCompiler({application:()=>{applications++;throw new Error('must not execute');}});
  const request={schema:'endpt',path:'records?id=eq.1',method:'PATCH',data_json:'{"name":"test"}'};
  for(const batch of [undefined,null,{},[],Array(1),Array(9).fill(request),[null],[{...request,schema:'public'}],
    [{...request,method:'PUT'}],[{...request,path:'https://external.invalid/records'}],
    [{...request,path:'rpc/read',method:'GET'}],[{...request,data_json:'invalid'}]])await assert.rejects(compiler.requestBatch(batch));
  assert.equal(applications,0);
});
