import {test} from 'node:test';
import assert from 'node:assert/strict';
import pg from 'pg';
import {randomUUID} from 'node:crypto';
import {PostgresCipherStore,RevisionConflict} from '../store.mjs';
import {member,hex} from '../integrity.mjs';

test('real PostgreSQL interface contains opaque IDs and ciphertext; all mutations commit atomically',
  {skip:!process.env.WARDEN_CIPHER_TEST_DSN},async()=>{
    const pool=new pg.Pool({connectionString:process.env.WARDEN_CIPHER_TEST_DSN,max:2});
    const connection={query:(s,a)=>pool.query(s,a),transaction:async callback=>{
      const client=await pool.connect();try{await client.query('BEGIN');const r=await callback(client);await client.query('COMMIT');return r;}
      catch(error){await client.query('ROLLBACK');throw error;}finally{client.release();}},snapshot:async callback=>{
      const client=await pool.connect();try{await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');const r=await callback(client);await client.query('COMMIT');return r;}
      catch(error){await client.query('ROLLBACK');throw error;}finally{client.release();}}};
    const dataset=randomUUID(),collection=randomUUID(),row=randomUUID(),revision=randomUUID();
    const payload='wdb1:'+Buffer.from(JSON.stringify(['enc:v1:'+'a'.repeat(64)])).toString('base64url');
    const store=new PostgresCipherStore(connection,dataset);
    try{
      await store.initialize(payload,revision,new Map([[collection,new Map([[row,payload]])]]));
      assert.deepEqual(await store.read(),{manifest:payload,revision,collections:new Map([[collection,new Map([[row,payload]])]])});
      const columns=(await pool.query("SELECT column_name FROM information_schema.columns WHERE table_schema='warden_cipher' ORDER BY table_name,ordinal_position")).rows;
      assert.deepEqual(columns.map(c=>c.column_name),['id','revision','manifest','id','payload']);
      let captured,release;
      const ready=new Promise(resolve=>{captured=resolve;}),resume=new Promise(resolve=>{release=resolve;});
      const scan=store.auditSnapshot(async readHead=>{
        assert.equal((await readHead()).revision,revision);captured();await resume;
        return [{id:collection,count:1,digest:hex(member(row,payload))}];
      });
      await ready;
      const afterAuditStart=randomUUID();
      await store.commit(revision,afterAuditStart,payload,[{collection,id:row,payload,kind:'put'}]);
      release();assert.equal(await scan,true); // concurrent write does not block or invalidate the older snapshot
      await assert.rejects(store.commit(randomUUID(),randomUUID(),payload,[]),RevisionConflict);
      const next=randomUUID();await store.commit(afterAuditStart,next,payload,[{collection,id:row,kind:'delete'}]);
      assert.equal((await store.read()).collections.get(collection).size,0);
      await assert.rejects(store.commit(next,randomUUID(),payload,[{collection,id:row,payload,kind:'put'}, {collection,id:randomUUID(),kind:'delete'}]));
      assert.equal((await store.head()).revision,next);assert.equal((await store.read()).collections.get(collection).size,0);
      await assert.rejects(store.auditSnapshot(async readHead=>{await readHead();return [{id:collection,count:1,digest:hex(member(row,payload))}];}));
      await pool.query('CREATE TABLE warden_cipher.unexpected(id int)');
      await assert.rejects(store.auditSnapshot(async readHead=>{await readHead();return [{id:collection,count:0,digest:hex(0n)}];}));
    }finally{await pool.query('DROP SCHEMA IF EXISTS warden_cipher CASCADE');await pool.end();}
});
