// Explicitly isolated synthetic SQL/durability benchmark, not a fleet claim.
import {randomUUID} from 'node:crypto';
import {setTimeout as sleep} from 'node:timers/promises';
import {connect} from './connection.mjs';
import {PostgresCipherStore} from './store.mjs';
import {CipherDatabase} from './engine.mjs';
import {JournalCheckpoint} from './journal_checkpoint.mjs';
import {FileCheckpoint} from './checkpoint.mjs';
import {nativeFactory} from './native.mjs';
import {Box} from './tests/box.mjs';

if(process.env.WARDEN_CIPHER_BENCHMARK!=='synthetic-only')throw new Error('Explicit isolated synthetic benchmark required');
const connection=await connect(process.env.CIPHER_CONNECTION_FILE);
if((await connection.query("SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname<>'information_schema' AND c.relkind IN('r','p','m','f') LIMIT 1")).rows.length)throw new Error('Benchmark requires an empty disposable database');
const dataset=randomUUID();await connection.acquireWriter(dataset);
const store=new PostgresCipherStore(connection,dataset),box=new Box(),checkpoint=new JournalCheckpoint(process.env.CIPHER_CHECKPOINT),options={projection:nativeFactory()};
const schema=`CREATE ROLE service_role;CREATE SCHEMA endpt;
 CREATE TABLE endpt.endpoints(id integer PRIMARY KEY,last_seen timestamptz,payload text NOT NULL);
 CREATE TABLE endpt.nonces(id uuid PRIMARY KEY,endpoint_id integer REFERENCES endpt.endpoints);
 CREATE TABLE endpt.metrics(id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,endpoint_id integer REFERENCES endpt.endpoints,value numeric);
 GRANT USAGE ON SCHEMA endpt TO service_role;GRANT SELECT,INSERT,UPDATE ON ALL TABLES IN SCHEMA endpt TO service_role;
 GRANT USAGE ON ALL SEQUENCES IN SCHEMA endpt TO service_role;`;
async function* seed(){for(let id=1;id<=10000;id++)yield {table:'endpt.endpoints',row:JSON.stringify({id,last_seen:null,payload:'synthetic-only-'.repeat(40)})};}
let engine=await CipherDatabase.create(store,box,new FileCheckpoint(process.env.CIPHER_CHECKPOINT),dataset,schema,seed(),[],options);
await engine.close();engine=await CipherDatabase.open(store,box,checkpoint,dataset,options);
let batchCount=0,writeRequests=0;engine.observeBatch=sample=>{batchCount++;writeRequests+=sample.requests;};
async function cycle(id){
  await engine.application(tx=>tx.query('INSERT INTO endpt.nonces VALUES($1,$2)',[randomUUID(),id]));
  await engine.application(tx=>tx.query('UPDATE endpt.endpoints SET last_seen=now() WHERE id=$1',[id]));
  await engine.application(tx=>tx.query('INSERT INTO endpt.metrics(endpoint_id,value) VALUES($1,12.5)',[id]));
  await engine.application(tx=>tx.query('SELECT id FROM endpt.endpoints WHERE id=$1',[id]),{readOnly:true});
}
const percentile=(values,p)=>values.length?Math.round([...values].sort((a,b)=>a-b)[Math.min(values.length-1,Math.ceil(values.length*p)-1)]):null;
async function stage(rate,seconds){
  const begin=performance.now(),pending=new Set(),latencies=[];let dropped=0,failed=0,completed=0;
  const initialBatches=batchCount,initialRequests=writeRequests;
  let audit;const timer=setTimeout(()=>{audit=engine.audit();audit.catch(()=>{});},Math.min(5000,seconds*500));
  for(let item=0;item<Math.floor(rate*seconds);item++){
    const scheduled=begin+item*1000/rate;await sleep(Math.max(0,scheduled-performance.now()));
    if(pending.size>=512){dropped++;continue;}
    let task;task=cycle(item%10000+1).then(()=>{completed++;latencies.push(performance.now()-scheduled);},()=>{failed++;}).finally(()=>pending.delete(task));pending.add(task);
  }
  await Promise.all(pending);clearTimeout(timer);if(audit)await audit;
  const elapsed=(performance.now()-begin)/1000;
  console.log(JSON.stringify({event:'synthetic_cipher_cycle_benchmark',endpoints:10000,target_per_second:rate,duration_seconds:seconds,
    completed,failed,dropped,drained_seconds:Math.round(elapsed*100)/100,completed_per_second:Math.round(completed/elapsed),
    p50_ms:percentile(latencies,.5),p95_ms:percentile(latencies,.95),p99_ms:percentile(latencies,.99),
    batches:batchCount-initialBatches,write_requests:writeRequests-initialRequests,audit_verified:!!audit,
    excludes:['HTTP','agent_authentication','custody_service','remote_relay','dashboard']}));
}
try{await stage(333,20);await stage(999,3);await engine.audit();}
finally{await engine.close();await connection.close();}
