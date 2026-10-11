import {createServer} from 'node:http';
import {readFile,chmod,unlink,lstat} from 'node:fs/promises';
import {timingSafeEqual} from 'node:crypto';
import {connect} from './connection.mjs';
import {PostgresCipherStore,identifier} from './store.mjs';
import {KeyServiceBox,unsealDocument,sealDocument} from './crypto.mjs';
import {JournalCheckpoint} from './journal_checkpoint.mjs';
import {CipherDatabase} from './engine.mjs';
import {RestCompiler} from './rest.mjs';
import {nativeFactory} from './native.mjs';
import {EnvelopeRegistry} from './replay.mjs';

const LIMIT=192*1024*1024;
const socket=process.env.CIPHER_SOCKET,tokenFile=process.env.CIPHER_TOKEN_FILE;
if(!socket?.startsWith('/')||!tokenFile?.startsWith('/'))throw new Error('Private runtime paths required');
const token=(await readFile(tokenFile,'utf8')).trim();
if(!/^[A-Za-z0-9_-]{43,128}$/.test(token))throw new Error('Invalid runtime credential');
const connection=await connect(process.env.CIPHER_CONNECTION_FILE);
const dataset=identifier(process.env.CIPHER_DATASET);
await connection.acquireWriter(dataset);
const box=new KeyServiceBox(process.env.KEY_SERVICE_SOCKET,process.env.KEY_SERVICE_TOKEN_FILE);
if(process.env.CIPHER_QUERY_ENGINE!=='native')throw new Error('Concurrent native projection configuration required');
const engine=await CipherDatabase.open(new PostgresCipherStore(connection,dataset),box,new JournalCheckpoint(process.env.CIPHER_CHECKPOINT),dataset,{projection:nativeFactory()});
const rest=new RestCompiler(engine);
// Bounded aggregate timings contain no SQL, identities, paths or data.
const phases=['queue','guard','query','persist','encode','intent','store','confirm'];
const emptyTimings=()=>Object.fromEntries(['read','write'].map(kind=>[kind,{count:0,...Object.fromEntries(phases.map(name=>[name,0]))}]));
let timings=emptyTimings();
let batches={count:0,requests:0,rejected:0};
engine.observeBatch=sample=>{batches.count++;batches.requests+=sample.requests;batches.rejected+=sample.rejected;};
engine.observeTransaction=sample=>{
  const group=timings[sample.readOnly?'read':'write'];group.count++;
  for(const name of phases)group[name]+=sample[name];
};
const timingTimer=setInterval(()=>{
  for(const [kind,group] of Object.entries(timings))if(group.count){
    const mean={};for(const name of phases)mean[name+'_ms']=Math.round(group[name]/group.count);
    console.log(JSON.stringify({event:'encrypted_query_timings',kind,count:group.count,...mean}));
  }
  timings=emptyTimings();
  if(batches.count)console.log(JSON.stringify({event:'encrypted_write_batches',...batches}));
  batches={count:0,requests:0,rejected:0};
},30000);timingTimer.unref();
let auditing=false;
async function audit(){
  if(auditing)return;auditing=true;const start=Date.now();
  try{await engine.audit();console.log(JSON.stringify({event:'encrypted_storage_audit',milliseconds:Date.now()-start,status:'verified'}));}
  catch{console.error('Encrypted storage audit failed; runtime closed');}
  finally{auditing=false;}
}
const auditTimer=setInterval(audit,300000);
// A trusted Linux operator can request a scan without restarting the service.
process.on('SIGUSR2',audit);
auditTimer.unref();
const used=new EnvelopeRegistry(),started=Date.now();let buffered=0;
function authorized(req){const supplied=Buffer.from(req.headers.authorization||''),expected=Buffer.from('Bearer '+token);return supplied.length===expected.length&&timingSafeEqual(supplied,expected);}
function reply(res,status,value){res.writeHead(status,{'Content-Type':'application/json','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'});res.end(JSON.stringify(value));}
const server=createServer(async(req,res)=>{
  if(!authorized(req))return reply(res,401,{error:'unauthorized'});
  if(req.method==='GET'&&req.url==='/health'){
    const closed=engine.closed||!connection.healthy||engine.db.healthy===false;
    return reply(res,closed?503:200,{status:closed?'closed':'ok'});
  }
  if(req.method!=='POST'||req.url!=='/v1/query')return reply(res,404,{error:'unknown_operation'});
  let retained=0;
  try{
    const chunks=[];let size=0;for await(const chunk of req){
      size+=chunk.length;if(size>LIMIT)throw new Error('Request bound');
      if(buffered+chunk.length>LIMIT){const error=new Error('Encrypted runtime busy');error.status=503;throw error;}
      buffered+=chunk.length;retained+=chunk.length;chunks.push(chunk);
    }
    const envelope=JSON.parse(Buffer.concat(chunks));
    if(Object.keys(envelope).sort().join(',')!=='id,payload')throw new Error('Invalid envelope');
    const id=identifier(envelope.id),now=Date.now();
    const document=JSON.parse(await unsealDocument(box,id,'database.request.v1:'+dataset,envelope.payload));
    if(document.id!==id||!Number.isSafeInteger(document.time)||document.time<started||Math.abs(now-document.time)>30000)throw new Error('Expired envelope');
    used.accept(id);
    let result;
    try{result=await rest.request(document.request);}
    catch(error){const code=error.code||'CIPHER_QUERY';result={status:engine.closed?503:error.status||(['23503','23505'].includes(code)?409:400),
      body:JSON.stringify({code,message:'Application query rejected'}),headers:{}};}
    const payload=await sealDocument(box,id,'database.response.v1:'+dataset,JSON.stringify({id,time:document.time,...result}));
    reply(res,200,{id,payload});
  }catch(error){reply(res,error.status===503?503:400,{error:error.status===503?'encrypted_runtime_busy':'invalid_encrypted_request'});}
  finally{buffered-=retained;}
});
server.requestTimeout=90000;server.headersTimeout=10000;server.maxConnections=128;
// The durable store's exclusive advisory lock proves that no prior writer
// remains. Only a stale socket (never a regular file) can then be removed.
try{const entry=await lstat(socket);if(!entry.isSocket())throw new Error('Invalid socket path');await unlink(socket);}
catch(error){if(error.code!=='ENOENT')throw error;}
await new Promise((resolve,reject)=>{server.once('error',()=>reject(new Error('Private runtime socket unavailable')));server.listen(socket,resolve);});
await chmod(socket,0o660);
async function stop(){clearInterval(auditTimer);clearInterval(timingTimer);server.close();await engine.close();await connection.close();await unlink(socket).catch(()=>{});}
process.once('SIGTERM',()=>stop().then(()=>process.exit(0)));
process.once('SIGINT',()=>stop().then(()=>process.exit(0)));
console.log('Encrypted application runtime ready');
