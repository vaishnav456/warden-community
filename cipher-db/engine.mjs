import { randomUUID } from 'node:crypto';
import { PGlite, types } from '@electric-sql/pglite';
import { pgcrypto } from '@electric-sql/pglite/contrib/pgcrypto';
import { sealDocument, unsealDocument, rowPurpose, manifestPurpose } from './crypto.mjs';
import { identifier } from './store.mjs';
import { stamp } from './checkpoint.mjs';
import {member,hex,integrity} from './integrity.mjs';
import {encodeManifest,decodeManifest} from './manifest.mjs';

const PRIVATE = '_warden_private_runtime';
const quote = value => '"' + value.replaceAll('"','""') + '"';
const relation = table => quote(table.schema) + '.' + quote(table.name);
const key = columns => JSON.stringify(columns);
// An authenticated 256-bit multiset accumulator plus count binds membership.
// Changes cost O(changed records); they never clone or hash the whole dataset.
function same(a,b) { return JSON.stringify(a) === JSON.stringify(b); }
async function memoryDatabase(schema) {
  const db = await PGlite.create({dataDir:'memory://', extensions:{pgcrypto},
    parsers:{[types.NUMERIC]:v=>v,[types.INT8]:v=>v}});
  try {
    await db.exec(schema);
    if ((await db.query('SELECT 1 FROM pg_namespace WHERE nspname=$1',[PRIVATE])).rows.length) throw new Error('Reserved runtime schema present');
    return db;
  } catch (error) { await db.close(); throw error; }
}
async function definitions(db) {
  const tables = await db.query(`SELECT n.nspname AS schema,c.relname AS name,c.relkind AS kind,
    ARRAY(SELECT a.attname FROM pg_index i JOIN unnest(i.indkey) WITH ORDINALITY k(attnum,ord) ON true
      JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum=k.attnum
      WHERE i.indrelid=c.oid AND i.indisprimary ORDER BY k.ord)::text[] AS pk,
    ARRAY(SELECT a.attname FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped AND a.attgenerated='' ORDER BY a.attnum)::text[] AS columns
    FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname NOT LIKE 'pg\\_%' ESCAPE '\\' AND n.nspname NOT IN ('information_schema',$1)
    AND c.relkind IN ('r','p','m','f') ORDER BY n.nspname,c.relname`,[PRIVATE]);
  for (const table of tables.rows) {
    if (table.kind!=='r' || !table.pk.length) throw new Error('Unsupported source relation; migration must not omit it');
  }
  return tables.rows;
}
async function sequences(db,known) {
  const result = known?{rows:known}:await db.query(`SELECT n.nspname AS schema,c.relname AS name FROM pg_class c
    JOIN pg_namespace n ON n.oid=c.relnamespace WHERE c.relkind='S'
    AND n.nspname NOT LIKE 'pg\\_%' ESCAPE '\\' AND n.nspname NOT IN ('information_schema',$1)
    ORDER BY n.nspname,c.relname`,[PRIVATE]);
  if(!result.rows.length)return [];
  const literal=value=>"'"+value.replaceAll("'","''")+"'";
  return (await db.query(result.rows.map(item=>'SELECT '+literal(item.schema)+'::text AS schema,'+
    literal(item.name)+'::text AS name,last_value::text,is_called FROM '+relation(item)).join(' UNION ALL '))).rows;
}
async function journal(db,tables) {
  await db.exec(`CREATE SCHEMA ${PRIVATE};
    CREATE TABLE ${PRIVATE}.journal(seq bigserial PRIMARY KEY,collection uuid,operation text,old_key jsonb,new_key jsonb,value text);
    CREATE FUNCTION ${PRIVATE}.record_write() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
    DECLARE prior json; upcoming json; old_keys jsonb:='[]'; new_keys jsonb:='[]'; position integer;
    BEGIN
      IF TG_OP<>'INSERT' THEN prior:=row_to_json(OLD); END IF;
      IF TG_OP<>'DELETE' THEN upcoming:=row_to_json(NEW); END IF;
      FOR position IN 1..TG_NARGS-1 LOOP
        IF prior IS NOT NULL THEN old_keys:=old_keys||jsonb_build_array(prior->>TG_ARGV[position]); END IF;
        IF upcoming IS NOT NULL THEN new_keys:=new_keys||jsonb_build_array(upcoming->>TG_ARGV[position]); END IF;
      END LOOP;
      INSERT INTO ${PRIVATE}.journal(collection,operation,old_key,new_key,value)
        VALUES(TG_ARGV[0]::uuid,TG_OP,old_keys,new_keys,upcoming::text);
      RETURN NULL;
    END $$;
    REVOKE ALL ON SCHEMA ${PRIVATE} FROM PUBLIC;`);
  for (const table of tables) {
    const args = [table.id,...table.pk].map(value=>"'"+value.replaceAll("'","''")+"'").join(',');
    await db.exec('CREATE TRIGGER '+quote('_warden_cipher_write')+' AFTER INSERT OR UPDATE OR DELETE ON '+relation(table)+
      ` FOR EACH ROW EXECUTE FUNCTION ${PRIVATE}.record_write(${args})`);
  }
}
async function insertRow(db,table,raw) {
  const columns = table.columns.map(quote).join(',');
  await db.query('INSERT INTO '+relation(table)+'('+columns+') OVERRIDING SYSTEM VALUE SELECT '+columns+
    ' FROM json_populate_record(NULL::'+relation(table)+',$1::json)',[raw]);
}
async function insertRows(db,table,rows) {
  if(!rows.length)return;
  const columns=table.columns.map(quote).join(',');
  await db.query('INSERT INTO '+relation(table)+'('+columns+') OVERRIDING SYSTEM VALUE SELECT '+columns+
    ' FROM json_populate_recordset(NULL::'+relation(table)+',$1::json)',['['+rows.join(',')+']']);
}

// SQL runs in application memory. The persistent database never executes a
// decrypting view/function, and its interface returns ciphertext records only.
export class CipherDatabase {
  constructor(store,box,checkpoint,dataset,{projection=memoryDatabase}={}) {
    this.store=store; this.box=box; this.checkpoint=checkpoint; this.dataset=identifier(dataset);
    this.tail=Promise.resolve(); this.closed=false;this.projection=projection;this.readers=new Set();this.writes=[];
  }
  async exclusive(callback) {
    const prior=this.tail; let release;
    this.tail=new Promise(resolve=>{release=resolve;});
    await prior;
    try { if(this.closed) throw new Error('Encrypted database closed'); return await callback(); }
    finally {release();}
  }
  async sealManifest(manifest) {
    return sealDocument(this.box,this.dataset,manifestPurpose(manifest.revision),await encodeManifest(manifest));
  }
  async pauseReaders() {
    if(!this.readPause)this.readPause=new Promise(resolve=>{this.resumeReaders=resolve;});
    await Promise.all([...this.readers].map(reader=>reader.done));
  }
  unpauseReaders() {this.resumeReaders?.();this.readPause=undefined;this.resumeReaders=undefined;}
  async failClosed() {this.closed=true;await this.pauseReaders();await this.db?.close();this.unpauseReaders();}
  static async create(store,box,checkpoint,dataset,schema,seed=[],sourceSequences=[],options={}) {
    const engine=new CipherDatabase(store,box,checkpoint,dataset,options);
    const db=await engine.projection(schema);
    try {
      const tables=(await definitions(db)).map(table=>({...table,id:randomUUID()}));
      const byName=new Map(tables.map(table=>[table.schema+'.'+table.name,table]));
      await db.exec('SET session_replication_role=replica');
      let pending=[],previous;
      for await(const item of seed) {
        const table=byName.get(item.table);
        if(!table) throw new Error('Untracked source table');
        if(previous&&previous!==table){await insertRows(db,previous,pending);pending=[];}
        previous=table;pending.push(item.row);
        if(pending.length>=128){await insertRows(db,table,pending);pending=[];}
      }
      if(pending.length)await insertRows(db,previous,pending);
      await db.exec('SET session_replication_role=origin');
      for(const item of sourceSequences) await db.query('SELECT setval($1::regclass,$2::bigint,$3)',[relation(item),item.last_value,item.is_called]);
      const collections=new Map(); const indexes=new Map();
      for(const table of tables) {
        const rows=new Map(); const keys=new Map();
        const keysSql=table.pk.map(column=>'r.'+quote(column)+'::text').join(',');
        const values=await db.query('SELECT row_to_json(r)::text AS value, ARRAY['+keysSql+'] AS key FROM '+relation(table)+' r');
        for(let offset=0;offset<values.rows.length;offset+=128) {
          await Promise.all(values.rows.slice(offset,offset+128).map(async item=>{
            const id=randomUUID(); keys.set(key(item.key),id);
            rows.set(id,await sealDocument(box,id,rowPurpose(dataset,table.id),JSON.stringify({key:item.key,row:item.value})));
          }));
        }
        table.count=rows.size; table.digest=integrity(rows);
        collections.set(table.id,rows); indexes.set(table.id,keys);
      }
      const manifest={v:1,dataset,revision:randomUUID(),schema,tables,sequences:await sequences(db)};
      const encrypted=await engine.sealManifest(manifest);
      const next={revision:manifest.revision,manifest:encrypted,collections};
      const checkpointValue=stamp(dataset,next);
      await checkpoint.prepare(undefined,checkpointValue);
      await store.initialize(encrypted,manifest.revision,collections);
      await checkpoint.finish(checkpointValue);
      await journal(db,tables);
      engine.db=db; engine.manifest=manifest; engine.state=next; engine.indexes=indexes;
      return engine;
    } catch(error) {await db.close(); throw error;}
  }
  static async open(store,box,checkpoint,dataset,options={}) {
    const engine=new CipherDatabase(store,box,checkpoint,dataset,options);
    await engine.restore(); return engine;
  }
  async restore() {
    await this.pauseReaders();
    try{return await this.restoreProjection();}finally{this.unpauseReaders();}
  }
  async restoreProjection() {
    const state=await this.store.read();
    await this.checkpoint.verify(stamp(this.dataset,state));
    const manifest=await decodeManifest(await unsealDocument(this.box,this.dataset,manifestPurpose(state.revision),state.manifest));
    if(manifest.v!==1 || manifest.dataset!==this.dataset || manifest.revision!==state.revision || !Array.isArray(manifest.tables)) throw new Error('Invalid encrypted database manifest');
    const tables=manifest.tables;
    if(state.collections.size!==tables.length || new Set(tables.map(table=>identifier(table.id))).size!==tables.length) throw new Error('Encrypted table membership mismatch');
    for(const table of tables) {
      const rows=state.collections.get(table.id);
      if(!rows || rows.size!==table.count || integrity(rows)!==table.digest) throw new Error('Encrypted record integrity mismatch');
    }
    const db=await this.projection(manifest.schema);
    try {
      const actual=await definitions(db);
      if(!same(actual,tables.map(({id,count,digest,...definition})=>definition))) throw new Error('Encrypted schema membership mismatch');
      const indexes=new Map();
      await db.exec('SET session_replication_role=replica');
      for(const table of tables) {
        const keys=new Map();
        let batch=[];
        const load=async()=>{
          const values=await Promise.all(batch.map(async([id,payload])=>{
            identifier(id);
            const value=JSON.parse(await unsealDocument(this.box,id,rowPurpose(this.dataset,table.id),payload));
            if(!Array.isArray(value.key)||value.key.length!==table.pk.length||typeof value.row!=='string'||keys.has(key(value.key)))throw new Error('Invalid encrypted record membership');
            keys.set(key(value.key),id);return value.row;
          }));
          await insertRows(db,table,values);batch=[];
        };
        for(const record of state.collections.get(table.id)) {
          batch.push(record);if(batch.length>=128)await load();
        }
        if(batch.length)await load();
        indexes.set(table.id,keys);
      }
      await db.exec('SET session_replication_role=origin');
      for(const item of manifest.sequences) await db.query('SELECT setval($1::regclass,$2::bigint,$3)',[relation(item),item.last_value,item.is_called]);
      // Restore planner statistics in memory after bulk loading the snapshot.
      await db.exec('ANALYZE');
      await journal(db,tables);
      const old=this.db;
      this.lazyRows=Boolean(db.concurrent&&this.store.records);
      // Native PostgreSQL owns the readable projection. Keep PK routing and
      // authenticated digests in JS, rather than a second full ciphertext copy.
      this.db=db; this.manifest=manifest; this.state=this.lazyRows?{...state,collections:new Map()}:state; this.indexes=indexes;
      if(old) await old.close();
    } catch(error) {await db.close(); throw error;}
  }
  async execute(sql,parameters=[]) {
    return this.transaction(tx=>tx.query(sql,parameters));
  }
  async application(callback,options={}) {
    return this.transaction(async tx=>{
      await tx.query('SET LOCAL ROLE service_role');
      const result=await callback(tx);
      await tx.query('RESET ROLE');
      return result;
    },options);
  }
  async audit() {
    if(this.auditPending)return this.auditPending;
    if(this.store.auditSnapshot){
      const task=this.store.auditSnapshot(readHead=>this.exclusive(async()=>{
        const head=await readHead();await this.checkpoint.verify(stamp(this.dataset,head));
        if(head.revision!==this.state.revision)throw new Error('Storage changed');
        return this.manifest.tables.map(({id,count,digest})=>({id,count,digest}));
      })).catch(async()=>{
        await this.exclusive(()=>this.failClosed()).catch(()=>{});
        throw new Error('Encrypted storage audit failed');
      });
      this.auditPending=task;
      try{return await task;}finally{this.auditPending=undefined;}
    }
    return this.exclusive(async()=>{
      try {
        const state=await this.store.read();await this.checkpoint.verify(stamp(this.dataset,state));
        if(state.revision!==this.state.revision||state.collections.size!==this.manifest.tables.length)throw new Error('Storage changed');
        for(const table of this.manifest.tables){const rows=state.collections.get(table.id);
          if(!rows||rows.size!==table.count||integrity(rows)!==table.digest)throw new Error('Storage changed');}
        return true;
      }catch{await this.failClosed();throw new Error('Encrypted storage audit failed');}
    });
  }
  async concurrentRead(callback) {
    while(this.readPause)await this.readPause;
    if(this.closed)throw new Error('Encrypted database closed');
    const started=performance.now();let guarded,queried,release,fatal=false;
    const reader={allowed:new Set([JSON.stringify(stamp(this.dataset,this.state)),...(this.pendingHeads||[])]),
      done:new Promise(resolve=>{release=resolve;})};
    this.readers.add(reader);
    try {
      // This connection is independent of the fenced durable writer. The
      // ticket records exactly the authenticated revisions possible during
      // this read's guard; it cannot authorize a pre-request database rollback.
      const observed=this.store.peekStamp?await this.store.peekStamp():stamp(this.dataset,await this.store.head());
      if(!reader.allowed.has(JSON.stringify(observed))){fatal=true;throw new Error('Encrypted head changed');}
      guarded=performance.now();
      const result=await this.db.transaction(callback,{readOnly:true});queried=performance.now();
      if(this.closed)throw new Error('Encrypted database closed');
      return result;
    }catch(error){
      const safe=new Error('Read-only application transaction failed');safe.code=error.code||'CIPHER_READ';safe.status=error.status;
      if(guarded===undefined||this.db.healthy===false)fatal=true;
      throw safe;
    }finally{
      this.readers.delete(reader);release();
      if(fatal)await this.failClosed();
      const ended=performance.now();
      this.observeTransaction?.({readOnly:true,queue:0,guard:(guarded??ended)-started,
        query:guarded===undefined?0:(queried??ended)-guarded,persist:0,encode:0,intent:0,store:0,confirm:0});
    }
  }
  async transaction(callback,{readOnly=false}={}) {
    if(readOnly&&this.db?.concurrent)return this.concurrentRead(callback);
    if(!readOnly&&this.db?.concurrent)return this.enqueueWrite(callback);
    return this.serialTransaction(callback,{readOnly});
  }
  enqueueWrite(callback) {
    if(this.closed)return Promise.reject(new Error('Encrypted database closed'));
    if(this.writes.length>=1024){const error=new Error('Encrypted writer queue full');error.status=503;return Promise.reject(error);}
    const promise=new Promise((resolve,reject)=>this.writes.push({callback,resolve,reject}));
    if(!this.writeTimer&&!this.flushing)this.writeTimer=setTimeout(()=>{this.writeTimer=undefined;this.flushWrites();},5);
    return promise;
  }
  async flushWrites() {
    this.flushing=true;
    try{
      while(this.writes.length){
        const batch=this.writes.splice(0,128),results=[];
        try{
          await this.serialTransaction(async tx=>{
            if(batch.length===1){results.push({value:await batch[0].callback(tx)});return;}
            // Requests execute in arrival order. Savepoints isolate rejected
            // requests; every successful result waits for the one durable commit.
            const deferred=(await tx.query(`SELECT quote_ident(n.nspname)||'.'||quote_ident(c.conname) AS name
              FROM pg_constraint c JOIN pg_namespace n ON n.oid=c.connamespace WHERE c.condeferrable AND c.condeferred`)).rows;
            for(const item of batch){
              const before=await sequences(tx,this.manifest.sequences);await tx.query('SAVEPOINT warden_request');
              try{
                const value=await item.callback(tx);await tx.query('SET CONSTRAINTS ALL IMMEDIATE');
                if(deferred.length)await tx.query('SET CONSTRAINTS '+deferred.map(row=>row.name).join(',')+' DEFERRED');
                await tx.query('RELEASE SAVEPOINT warden_request');results.push({value});
              }catch(error){
                await tx.query('ROLLBACK TO SAVEPOINT warden_request');await tx.query('RELEASE SAVEPOINT warden_request');
                // PostgreSQL sequences survive savepoint rollback. A rejected
                // request must not change the captured counters of later callers.
                for(const sequence of before)await tx.query('SELECT setval($1::regclass,$2::bigint,$3)',[relation(sequence),sequence.last_value,sequence.is_called]);
                const safe=new Error('Application transaction rejected');safe.code=error.code||'CIPHER_TRANSACTION';safe.status=error.status;results.push({error:safe});
              }
            }
          });
          for(let i=0;i<batch.length;i++)results[i].error?batch[i].reject(results[i].error):batch[i].resolve(results[i].value);
          this.observeBatch?.({requests:batch.length,rejected:results.filter(result=>result.error).length});
        }catch(error){for(const item of batch)item.reject(error);}
      }
    }finally{this.flushing=false;}
  }
  async serialTransaction(callback,{readOnly=false}={}) {
    const started=performance.now();let entered,guarded,queried;
    const phases={encode:0,intent:0,store:0,confirm:0};
    try{return await this.exclusive(async()=>{
      entered=performance.now();
      try{
        const current=await this.store.head();
        await this.checkpoint.verify(stamp(this.dataset,current));
        if(current.revision!==this.state.revision) await this.restore();
      }catch{await this.failClosed();throw new Error('Encrypted database guard failed');}
      guarded=performance.now();
      let committed=false;
      try {
        return await this.db.transaction(async tx=>{
          if(readOnly)await tx.query('SET TRANSACTION READ ONLY');
          const result=await callback(tx);
          queried=performance.now();
          // PostgreSQL rejects writes and sequence changes in this path.
          if(readOnly)return result;
          // Deferred constraints/triggers must finish before the durable
          // encrypted commit; a rejected SQL commit must not persist its rows.
          await tx.query('SET CONSTRAINTS ALL IMMEDIATE');
          const events=(await tx.query(`SELECT collection,operation,old_key,new_key,value FROM ${PRIVATE}.journal ORDER BY seq`)).rows;
          const nextSequences=await sequences(tx,this.manifest.sequences);
          if(!events.length && same(nextSequences,this.manifest.sequences)) return result;
          const updates=new Map(); const indexes=new Map();
          for(const event of events) {
            const table=this.manifest.tables.find(table=>table.id===event.collection);
            if(!table) throw new Error('Untracked encrypted write');
            if(!updates.has(table.id)) {updates.set(table.id,new Map()); indexes.set(table.id,new Map());}
            const rows=updates.get(table.id); const keys=indexes.get(table.id);
            const lookup=value=>keys.has(value)?keys.get(value):this.indexes.get(table.id).get(value);
            let id;
            if(event.operation!=='INSERT') {
              id=lookup(key(event.old_key));
              if(!id) throw new Error('Encrypted write identity mismatch');
              keys.set(key(event.old_key),null);
            } else id=randomUUID();
            if(event.operation==='DELETE') rows.set(id,null);
            else {
              if(lookup(key(event.new_key))) throw new Error('Encrypted write identity conflict');
              keys.set(key(event.new_key),id);
              rows.set(id,{key:event.new_key,row:event.value});
            }
          }
          // Collapse repeated changes to one record, then use the custody
          // adapter's bounded batch API instead of a socket roundtrip per row.
          for(const [collection,rows] of updates){
            const records=[...rows].filter(([,value])=>value!==null);
            for(let offset=0;offset<records.length;offset+=128)await Promise.all(records.slice(offset,offset+128).map(async([id,value])=>{
              rows.set(id,await sealDocument(this.box,id,rowPurpose(this.dataset,collection),JSON.stringify(value)));
            }));
          }
          const changes=[];const stats=new Map();
          for(const [collection,updates_] of updates) {
            const rows=this.lazyRows?await this.store.records(collection,[...updates_.keys()]):this.state.collections.get(collection);
            const table=this.manifest.tables.find(item=>item.id===collection);
            let sum=BigInt('0x'+table.digest),count=table.count;
            for(const [id,payload] of updates_) {
              const previous=rows.get(id);
              if(previous!==undefined) {sum-=member(id,previous);count--;}
              if(payload===null) {
                // A row inserted and deleted in one transaction was never stored.
                if(previous!==undefined) changes.push({collection,id,kind:'delete'});
              } else {sum+=member(id,payload);count++;changes.push({collection,id,payload,kind:'put'});}
            }
            stats.set(collection,{count,digest:hex(sum)});
          }
          const manifest={...this.manifest,revision:randomUUID(),sequences:nextSequences,tables:this.manifest.tables.map(table=>({...table,...stats.get(table.id)}))};
          let phase=performance.now();
          const next={revision:manifest.revision,manifest:await this.sealManifest(manifest),collections:this.state.collections};
          this.pendingHeads=[JSON.stringify(stamp(this.dataset,this.state)),JSON.stringify(stamp(this.dataset,next))];
          for(const reader of this.readers)for(const head of this.pendingHeads)reader.allowed.add(head);
          phases.encode=performance.now()-phase;phase=performance.now();
          await this.checkpoint.prepare(stamp(this.dataset,this.state),stamp(this.dataset,next));
          phases.intent=performance.now()-phase;phase=performance.now();
          await this.store.commit(this.state.revision,next.revision,next.manifest,changes);
          phases.store=performance.now()-phase;phase=performance.now();
          committed=true;
          await this.checkpoint.finish(stamp(this.dataset,next));
          phases.confirm=performance.now()-phase;
          await tx.query(`DELETE FROM ${PRIVATE}.journal`);
          if(!this.lazyRows)for(const change of changes) {
            const rows=next.collections.get(change.collection);
            if(change.kind==='delete') rows.delete(change.id);else rows.set(change.id,change.payload);
          }
          this.state=next; this.manifest=manifest;
          for(const [collection,keys] of indexes) for(const [key_,id] of keys) {
            if(id===null) this.indexes.get(collection).delete(key_);else this.indexes.get(collection).set(key_,id);
          }
          return result;
        },{readOnly});
      } catch(error) {
        // A cold commit is authoritative. A failed local commit/checkpoint must
        // recover it before another query, rather than return a stale cache.
        await this.pauseReaders();
        try {
          const head=await this.store.head();
          await this.checkpoint.verify(stamp(this.dataset,head));
          if(head.revision!==this.state.revision||committed)await this.restoreProjection();
          else if(!readOnly)for(const item of this.manifest.sequences)await this.db.query('SELECT setval($1::regclass,$2::bigint,$3)',[relation(item),item.last_value,item.is_called]);
        } catch {this.closed=true; await this.db.close();}
        finally{this.unpauseReaders();}
        const safe=new Error(committed?'Encrypted commit requires recovery':'Application transaction failed');
        safe.code=error.code || 'CIPHER_TRANSACTION';safe.status=error.status;throw safe;
      }finally{this.pendingHeads=undefined;}
    });}finally{
      if(entered!==undefined&&this.observeTransaction){
        const ended=performance.now();
        this.observeTransaction({readOnly,queue:entered-started,guard:(guarded??ended)-entered,
          query:guarded===undefined?0:(queried??ended)-guarded,
          persist:queried===undefined?0:ended-queried,...phases});
      }
    }
  }
  async close() {
    if(this.closed)return;
    if(this.writeTimer){clearTimeout(this.writeTimer);this.writeTimer=undefined;}
    if(this.writes.length&&!this.flushing)await this.flushWrites();
    await this.exclusive(()=>this.failClosed());
    for(const item of this.writes.splice(0))item.reject(new Error('Encrypted database closed'));
  }
}
