// One-way bootstrap into an EMPTY ciphertext database. The source remains
// untouched. Cutover and removal of legacy storage are separate operator steps.
import {readFile} from 'node:fs/promises';
import {connect} from './connection.mjs';
import {PostgresCipherStore,identifier} from './store.mjs';
import {KeyServiceBox} from './crypto.mjs';
import {FileCheckpoint} from './checkpoint.mjs';
import {CipherDatabase} from './engine.mjs';
const quote=value=>'"'+value.replaceAll('"','""')+'"';
async function main(){
  const source=await connect(process.env.CIPHER_SOURCE_CONNECTION_FILE),target=await connect(process.env.CIPHER_CONNECTION_FILE);
  let engine;
  try{
    await source.transaction(async tx=>{
      await tx.query('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY');
      const roles=(await tx.query("SELECT rolname,rolbypassrls FROM pg_roles WHERE rolname NOT LIKE 'pg_%' ORDER BY rolname")).rows;
      let schema=await readFile(process.env.CIPHER_SOURCE_SCHEMA,'utf8');
      if(schema.split('\n').some(line=>line.startsWith('\\')&&!line.startsWith('\\restrict ')&&!line.startsWith('\\unrestrict ')))throw new Error('Unsupported dump directive');
      schema=schema.split('\n').filter(line=>!line.startsWith('\\')).join('\n');
      const prefix=roles.map(({rolname,rolbypassrls})=>`DO $$ BEGIN IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=${"'"+rolname.replaceAll("'","''")+"'"}) THEN CREATE ROLE ${quote(rolname)};END IF;END $$;`+
        (rolbypassrls?'ALTER ROLE '+quote(rolname)+' BYPASSRLS;':'')).join('\n');
      schema=prefix+'\n'+schema;
      const tables=(await tx.query(`SELECT n.nspname AS schema,c.relname AS name,c.relkind AS kind,
        EXISTS(SELECT 1 FROM pg_index i WHERE i.indrelid=c.oid AND i.indisprimary) AS pk
        FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname NOT LIKE 'pg\\_%' ESCAPE '\\' AND n.nspname<>'information_schema'
        AND c.relkind IN('r','p','m','f') ORDER BY n.nspname,c.relname`)).rows;
      if(!tables.length||tables.some(t=>t.kind!=='r'||!t.pk))throw new Error('Unsupported source relation');
      const sourceSequences=(await tx.query(`SELECT n.nspname AS schema,c.relname AS name FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE c.relkind='S' AND n.nspname NOT LIKE 'pg\\_%' ESCAPE '\\' AND n.nspname<>'information_schema' ORDER BY n.nspname,c.relname`)).rows;
      for(const item of sourceSequences)Object.assign(item,(await tx.query('SELECT last_value::text,is_called FROM '+quote(item.schema)+'.'+quote(item.name))).rows[0]);
      const counts=new Map();
      async function* records(){
        for(const table of tables){
          const ref=quote(table.schema)+'.'+quote(table.name);let count=0;
          await tx.query('DECLARE warden_capture NO SCROLL CURSOR FOR SELECT row_to_json(r)::text AS value FROM '+ref+' r');
          try{while(true){const batch=await tx.query('FETCH FORWARD 1024 FROM warden_capture');if(!batch.rows.length)break;
            for(const row of batch.rows){count++;yield {table:table.schema+'.'+table.name,row:row.value};}}}
          finally{await tx.query('CLOSE warden_capture');}
          counts.set(table.schema+'.'+table.name,count);
        }
      }
      const dataset=identifier(process.env.CIPHER_DATASET),store=new PostgresCipherStore(target,dataset);
      const box=new KeyServiceBox(process.env.KEY_SERVICE_SOCKET,process.env.KEY_SERVICE_TOKEN_FILE),checkpoint=new FileCheckpoint(process.env.CIPHER_CHECKPOINT);
      engine=await CipherDatabase.create(store,box,checkpoint,dataset,schema,records(),sourceSequences);
      if(engine.manifest.tables.length!==tables.length||engine.manifest.tables.some(t=>t.count!==counts.get(t.schema+'.'+t.name)))throw new Error('Source membership mismatch');
      await engine.close();engine=await CipherDatabase.open(store,box,checkpoint,dataset);
      // Full raw JSON hashes verify values and multiplicity in each snapshot,
      // beyond the ciphertext authentication performed by open().
      for(const table of tables){
        const ref=quote(table.schema)+'.'+quote(table.name);
        const sql="SELECT count(*)::text AS count,COALESCE(sum(('x'||substr(md5(row_to_json(r)::text),1,16))::bit(64)::bigint::numeric),0)::text AS digest FROM "+ref+' r';
        const before=(await tx.query(sql)).rows[0],after=(await engine.execute(sql)).rows[0];
        if(JSON.stringify(before)!==JSON.stringify(after))throw new Error('Source value verification failed');
      }
      console.log(JSON.stringify({verified:true,tables:tables.length,rows:[...counts.values()].reduce((a,b)=>a+b,0),source_modified:false}));
    });
  }finally{if(engine)await engine.close();await source.close();await target.close();}
}
main().catch(()=>{console.error('Ciphertext migration failed; private source remains unchanged');process.exitCode=1;});
