// A disposable PostgreSQL projection inside the trusted runtime container.
// Neither its socket nor readable files are mounted in the web application.
import pg from 'pg';
import {mkdtemp,readFile,statfs,chmod,rm} from 'node:fs/promises';
import {join} from 'node:path';
import {spawn} from 'node:child_process';

function command(name,args) {
  return new Promise((resolve,reject)=>{
    const child=spawn(name,args,{stdio:'ignore'});
    child.once('error',()=>reject(new Error('Volatile projection process unavailable')));
    child.once('exit',code=>code===0?resolve():reject(new Error('Volatile projection initialization failed')));
  });
}
export async function verifyVolatileRoot(root) {
  if(process.platform!=='linux'||!/^\/[A-Za-z0-9_/-]+$/.test(root||''))throw new Error('Linux volatile projection mount required');
  if((await statfs(root)).type!==0x01021994)throw new Error('Projection must reside on tmpfs');
  if((await readFile('/sys/fs/cgroup/memory.swap.max','utf8')).trim()!=='0')throw new Error('Projection swap must be disabled');
  const limits=await readFile('/proc/self/limits','utf8');
  if(!/^Max core file size\s+0\s+0\s/m.test(limits))throw new Error('Projection core dumps must be disabled');
}
export function nativeFactory(root=process.env.CIPHER_PROJECTION_ROOT) {
  return async schema=>{
    await verifyVolatileRoot(root);
    const directory=await mkdtemp(join(root,'projection-'));await chmod(directory,0o700);
    const data=join(directory,'data');let control,pool,closed=false,healthy=true;
    const stop=async()=>{
      if(closed)return;closed=true;
      await pool?.end();await control?.end().catch(()=>{});
      await command('pg_ctl',['-D',data,'-m','immediate','-w','stop']).catch(()=>{});
      await rm(directory,{recursive:true,force:true});
    };
    try {
      await command('initdb',['-D',data,'-U','warden_projection','--auth-local=trust','--auth-host=reject','--encoding=UTF8','--locale=C','--lc-ctype=C.UTF-8']);
      // All PostgreSQL files, including WAL and spills, are under this private
      // tmpfs directory. Durability belongs exclusively to the ciphertext store.
      const options=["listen_addresses=''",`unix_socket_directories='${directory}'`,'unix_socket_permissions=0700',
        'max_connections=24','shared_buffers=128MB','work_mem=4MB','maintenance_work_mem=64MB',
        'max_parallel_workers=0','fsync=off','synchronous_commit=off','full_page_writes=off',
        'logging_collector=off','log_statement=none','log_min_messages=panic',
        'log_min_error_statement=panic','log_error_verbosity=terse','statement_timeout=30000',
        'idle_in_transaction_session_timeout=60000','temp_file_limit=262144'].map(value=>'-c '+value).join(' ');
      await command('pg_ctl',['-D',data,'-l','/dev/null','-o',options,'-w','start']);
      const config={host:directory,user:'warden_projection',database:'postgres',connectionTimeoutMillis:10000};
      control=new pg.Client(config);control.on('error',()=>{healthy=false;});await control.connect();
      await control.query(schema);
      if((await control.query("SELECT 1 FROM pg_namespace WHERE nspname='_warden_private_runtime'")).rows.length)throw new Error('Reserved projection schema present');
      pool=new pg.Pool({...config,max:16,idleTimeoutMillis:30000});pool.on('error',()=>{healthy=false;});
      const db={concurrent:true,get healthy(){return healthy&&!closed;},query:(sql,args)=>control.query(sql,args),exec:sql=>control.query(sql),close:stop,
        async transaction(callback,{readOnly=false}={}) {
          const client=readOnly?await pool.connect():control;
          try {
            await client.query(readOnly?'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY':'BEGIN');
            const result=await callback({query:(sql,args)=>client.query(sql,args),exec:sql=>client.query(sql)});
            await client.query('COMMIT');return result;
          }catch(error){await client.query('ROLLBACK').catch(()=>{});throw error;}
          finally{if(readOnly)client.release();}
        }};
      return db;
    }catch(error){await stop();throw error;}
  };
}
