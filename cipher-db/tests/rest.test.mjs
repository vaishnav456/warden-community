import {test} from 'node:test';
import assert from 'node:assert/strict';
import {PGlite} from '@electric-sql/pglite';
import {RestCompiler} from '../rest.mjs';
test('query compatibility: joins, inner filters, pagination, atomic routines and exact JSON numbers',async()=>{
  const db=new PGlite();await db.exec(`CREATE SCHEMA endpt;
  CREATE TABLE endpt.companies(id bigint PRIMARY KEY,name text,active boolean);
  CREATE TABLE endpt.endpoints(id integer PRIMARY KEY,company_id bigint REFERENCES endpt.companies,name text,tags text[]);
  CREATE FUNCTION endpt.bump(p_id bigint,p_name text DEFAULT 'default') RETURNS jsonb LANGUAGE plpgsql AS $$
    BEGIN UPDATE endpt.companies SET name=p_name WHERE id=p_id;RETURN jsonb_build_object('ok',FOUND);END $$;
  CREATE FUNCTION endpt.no_args() RETURNS integer LANGUAGE sql AS $$SELECT 7$$;`);
  const compiler=new RestCompiler({application:fn=>db.transaction(fn)});
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
    const routine=await request('rpc/bump','POST','{"p_id":9007199254740993,"p_name":"Routine"}');assert.deepEqual(JSON.parse(routine.body),{ok:true});
    await assert.rejects(request('rpc/missing','POST','{}'),error=>error.code==='PGRST202'&&error.status===404);
    assert.equal((await request('rpc/no_args','POST','{}')).body,'7');
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
