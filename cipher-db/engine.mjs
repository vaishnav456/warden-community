import { createHash, randomUUID } from 'node:crypto';
import { PGlite, types } from '@electric-sql/pglite';
import { pgcrypto } from '@electric-sql/pglite/contrib/pgcrypto';
import { sealDocument, unsealDocument, rowPurpose, manifestPurpose } from './crypto.mjs';
import { identifier } from './store.mjs';
import { stamp } from './checkpoint.mjs';

const PRIVATE = '_warden_private_runtime';
const quote = value => '"' + value.replaceAll('"','""') + '"';
const relation = table => quote(table.schema) + '.' + quote(table.name);
const key = columns => JSON.stringify(columns);
const hash = value => createHash('sha256').update(value).digest('hex');

const MOD=1n<<256n;
const member=(id,payload)=>BigInt('0x'+hash(id+':'+hash(payload)));
const hex=value=>((value%MOD+MOD)%MOD).toString(16).padStart(64,'0');
// An authenticated 256-bit multiset accumulator plus count binds membership.
// Changes cost O(changed records); they never clone or hash the whole dataset.
function integrity(rows) {let sum=0n;for(const [id,payload] of rows) sum+=member(id,payload);return hex(sum);}
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
      WHERE i.indrelid=c.oid AND i.indisprimary ORDER BY k.ord) AS pk,
    ARRAY(SELECT a.attname FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped AND a.attgenerated='' ORDER BY a.attnum) AS columns
    FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname NOT LIKE 'pg\\_%' ESCAPE '\\' AND n.nspname NOT IN ('information_schema',$1)
    AND c.relkind IN ('r','p','m','f') ORDER BY n.nspname,c.relname`,[PRIVATE]);
  for (const table of tables.rows) {
    if (table.kind!=='r' || !table.pk.length) throw new Error('Unsupported source relation; migration must not omit it');
  }
  return tables.rows;
}
async function sequences(db) {
  const result = await db.query(`SELECT n.nspname AS schema,c.relname AS name FROM pg_class c
    JOIN pg_namespace n ON n.oid=c.relnamespace WHERE c.relkind='S'
    AND n.nspname NOT LIKE 'pg\\_%' ESCAPE '\\' AND n.nspname NOT IN ('information_schema',$1)
    ORDER BY n.nspname,c.relname`,[PRIVATE]);
  const values = [];
  for (const item of result.rows) {
    const value = (await db.query('SELECT last_value::text,is_called FROM '+relation(item))).rows[0];
    values.push({...item,...value});
  }
  return values;
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
  constructor(store,box,checkpoint,dataset) {
    this.store=store; this.box=box; this.checkpoint=checkpoint; this.dataset=identifier(dataset);
    this.tail=Promise.resolve(); this.closed=false;
  }
  async exclusive(callback) {
    const prior=this.tail; let release;
    this.tail=new Promise(resolve=>{release=resolve;});
    await prior;
    try { if(this.closed) throw new Error('Encrypted database closed'); return await callback(); }
    finally {release();}
  }
  async sealManifest(manifest) {
    return sealDocument(this.box,this.dataset,manifestPurpose(manifest.revision),JSON.stringify(manifest));
  }
  static async create(store,box,checkpoint,dataset,schema,seed=[],sourceSequences=[]) {
    const engine=new CipherDatabase(store,box,checkpoint,dataset);
    const db=await memoryDatabase(schema);
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
  static async open(store,box,checkpoint,dataset) {
    const engine=new CipherDatabase(store,box,checkpoint,dataset);
    await engine.restore(); return engine;
  }
  async restore() {
    const state=await this.store.read();
    await this.checkpoint.verify(stamp(this.dataset,state));
    const manifest=JSON.parse(await unsealDocument(this.box,this.dataset,manifestPurpose(state.revision),state.manifest));
    if(manifest.v!==1 || manifest.dataset!==this.dataset || manifest.revision!==state.revision || !Array.isArray(manifest.tables)) throw new Error('Invalid encrypted database manifest');
    const tables=manifest.tables;
    if(state.collections.size!==tables.length || new Set(tables.map(table=>identifier(table.id))).size!==tables.length) throw new Error('Encrypted table membership mismatch');
    for(const table of tables) {
      const rows=state.collections.get(table.id);
      if(!rows || rows.size!==table.count || integrity(rows)!==table.digest) throw new Error('Encrypted record integrity mismatch');
    }
    const db=await memoryDatabase(manifest.schema);
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
      await journal(db,tables);
      const old=this.db;
      this.db=db; this.manifest=manifest; this.state=state; this.indexes=indexes;
      if(old) await old.close();
    } catch(error) {await db.close(); throw error;}
  }
  async execute(sql,parameters=[]) {
    return this.transaction(tx=>tx.query(sql,parameters));
  }
  async application(callback) {
    return this.transaction(async tx=>{
      await tx.query('SET LOCAL ROLE service_role');
      const result=await callback(tx);
      await tx.query('RESET ROLE');
      return result;
    });
  }
  async audit() {
    return this.exclusive(async()=>{
      try {
        const state=await this.store.read();await this.checkpoint.verify(stamp(this.dataset,state));
        if(state.revision!==this.state.revision||state.collections.size!==this.manifest.tables.length)throw new Error('Storage changed');
        for(const table of this.manifest.tables){const rows=state.collections.get(table.id);
          if(!rows||rows.size!==table.count||integrity(rows)!==table.digest)throw new Error('Storage changed');}
        return true;
      }catch{this.closed=true;await this.db.close();throw new Error('Encrypted storage audit failed');}
    });
  }
  async transaction(callback) {
    return this.exclusive(async()=>{
      const current=await this.store.head();
      await this.checkpoint.verify(stamp(this.dataset,current));
      if(current.revision!==this.state.revision) await this.restore();
      let committed=false;
      try {
        return await this.db.transaction(async tx=>{
          const result=await callback(tx);
          // Deferred constraints/triggers must finish before the durable
          // encrypted commit; a rejected SQL commit must not persist its rows.
          await tx.query('SET CONSTRAINTS ALL IMMEDIATE');
          const events=(await tx.query(`SELECT collection,operation,old_key,new_key,value FROM ${PRIVATE}.journal ORDER BY seq`)).rows;
          const nextSequences=await sequences(tx);
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
              rows.set(id,await sealDocument(this.box,id,rowPurpose(this.dataset,table.id),JSON.stringify({key:event.new_key,row:event.value})));
            }
          }
          const changes=[];const stats=new Map();
          for(const [collection,updates_] of updates) {
            const rows=this.state.collections.get(collection);
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
          const next={revision:manifest.revision,manifest:await this.sealManifest(manifest),collections:this.state.collections};
          await this.checkpoint.prepare(stamp(this.dataset,this.state),stamp(this.dataset,next));
          await this.store.commit(this.state.revision,next.revision,next.manifest,changes);
          committed=true;
          await this.checkpoint.finish(stamp(this.dataset,next));
          await tx.query(`DELETE FROM ${PRIVATE}.journal`);
          for(const change of changes) {
            const rows=next.collections.get(change.collection);
            if(change.kind==='delete') rows.delete(change.id);else rows.set(change.id,change.payload);
          }
          this.state=next; this.manifest=manifest;
          for(const [collection,keys] of indexes) for(const [key_,id] of keys) {
            if(id===null) this.indexes.get(collection).delete(key_);else this.indexes.get(collection).set(key_,id);
          }
          return result;
        });
      } catch(error) {
        // A cold commit is authoritative. A failed local commit/checkpoint must
        // recover it before another query, rather than return a stale cache.
        try {
          const head=await this.store.head();
          await this.checkpoint.verify(stamp(this.dataset,head));
          if(head.revision!==this.state.revision||committed)await this.restore();
          else for(const item of this.manifest.sequences)await this.db.query('SELECT setval($1::regclass,$2::bigint,$3)',[relation(item),item.last_value,item.is_called]);
        } catch {this.closed=true; await this.db.close();}
        const safe=new Error(committed?'Encrypted commit requires recovery':'Application transaction failed');
        safe.code=error.code || 'CIPHER_TRANSACTION';safe.status=error.status;throw safe;
      }
    });
  }
  async close() {if(this.closed)return;await this.exclusive(async()=>{this.closed=true; await this.db.close();});}
}
