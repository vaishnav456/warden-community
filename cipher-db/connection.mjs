import pg from 'pg';
import {readFile} from 'node:fs/promises';
export async function connect(path) {
  if(!path?.startsWith('/'))throw new Error('Private absolute connection file required');
  const config=JSON.parse(await readFile(path,'utf8'));
  const client=new pg.Client({...config,application_name:'warden-cipher-store',connectionTimeoutMillis:10000});
  let healthy=true;
  const readers=new Set();
  client.on('error',()=>{healthy=false;}); // No connection errors/DSNs are logged.
  await client.connect();
  const query=(sql,args)=>{if(!healthy)throw new Error('Ciphertext storage unavailable');return client.query(sql,args);};
  return {
    query,
    get healthy(){return healthy;},
    async acquireWriter(dataset){
      if(!(await query('SELECT pg_try_advisory_lock(hashtextextended($1,0)) AS acquired',[dataset])).rows[0].acquired)throw new Error('Encrypted database already has a writer');
    },
    async transaction(callback){
      try {await query('BEGIN');const result=await callback({query});await query('COMMIT');return result;}
      catch(error){try{await query('ROLLBACK');}catch{}throw error;}
    },
    async snapshot(callback){
      if(!healthy)throw new Error('Ciphertext storage unavailable');
      const reader=new pg.Client({...config,application_name:'warden-cipher-audit',connectionTimeoutMillis:10000});
      readers.add(reader);reader.on('error',()=>{});
      try{
        await reader.connect();await reader.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
        const result=await callback({query:(sql,args)=>reader.query(sql,args)});
        await reader.query('COMMIT');return result;
      }catch(error){try{await reader.query('ROLLBACK');}catch{}throw error;}
      finally{readers.delete(reader);await reader.end();}
    },
    close:async()=>{await Promise.allSettled([...readers].map(reader=>reader.end()));await client.end();},
  };
}
