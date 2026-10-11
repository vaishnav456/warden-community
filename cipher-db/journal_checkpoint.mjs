import {createHash,randomUUID} from 'node:crypto';
import {open,rename} from 'node:fs/promises';
import {dirname,isAbsolute} from 'node:path';
import {FileCheckpoint,CheckpointMismatch} from './checkpoint.mjs';

const MAX=8*1024*1024;
const equal=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const digest=value=>createHash('sha256').update(value).digest('hex');
const valid=value=>value&&Object.keys(value).sort().join(',')==='dataset,digest,revision'&&
  /^[0-9a-f-]{36}$/.test(value.dataset)&&/^[0-9a-f-]{36}$/.test(value.revision)&&/^[0-9a-f]{64}$/.test(value.digest);
function line(record){const raw=JSON.stringify(record);return JSON.stringify({record,checksum:digest(raw)})+'\n';}

// The private journal is outside PostgreSQL. Two durable append barriers per
// commit replace repeated file creation/rename/directory barriers. It contains
// opaque checkpoint stamps only. Its inode is made durable before first use.
export class JournalCheckpoint {
  constructor(path){
    if(!isAbsolute(path))throw new Error('Absolute checkpoint path required');
    this.path=path+'.journal';this.legacyPath=path;this.legacy=new FileCheckpoint(path);
  }
  async directorySync(){const file=await open(dirname(this.path),'r');try{await file.sync();}finally{await file.close();}}
  async replace(){
    if(this.failed)throw new CheckpointMismatch();
    const temporary=this.path+'.'+randomUUID()+'.tmp';
    const data=line({kind:'snapshot',head:this.head,pending:this.pending??null});
    try{
      const file=await open(temporary,'wx',0o600);
      try{await file.writeFile(data);await file.sync();}finally{await file.close();}
      await rename(temporary,this.path);await this.directorySync();
      this.bytes=Buffer.byteLength(data);
    }catch(error){this.failed=true;throw error;}
  }
  async load(){
    if(this.failed)throw new CheckpointMismatch();
    if(this.loaded)return;
    let file;
    try{file=await open(this.path,'r');}
    catch(error){if(error.code==='ENOENT')return;throw error;}
    let data;
    try{
      const stat=await file.stat();
      if(!stat.isFile()||stat.size>MAX+4096||(stat.mode&0o077))throw new CheckpointMismatch();
      data=await file.readFile();
    }finally{await file.close();}
    const end=data.lastIndexOf(10)+1;
    if(!end)throw new CheckpointMismatch();
    let initialized=false;
    for(const raw of data.subarray(0,end).toString('utf8').split('\n').slice(0,-1)){
      let envelope;
      try{envelope=JSON.parse(raw);}catch{throw new CheckpointMismatch();}
      if(!envelope||Object.keys(envelope).sort().join(',')!=='checksum,record'||digest(JSON.stringify(envelope.record))!==envelope.checksum)throw new CheckpointMismatch();
      const record=envelope.record;
      if(!initialized){
        if(!record||Object.keys(record).sort().join(',')!=='head,kind,pending'||record.kind!=='snapshot'||!valid(record.head)||record.pending!==null)throw new CheckpointMismatch();
        this.head=record.head;this.pending=record.pending;
        initialized=true;
      }else if(record?.kind==='prepare'){
        if(Object.keys(record).sort().join(',')!=='after,before,kind'||this.pending||!equal(record.before,this.head)||!valid(record.after)||record.after.dataset!==this.head.dataset)throw new CheckpointMismatch();
        this.pending={before:record.before,after:record.after};
      }else if(record?.kind==='finish'){
        if(Object.keys(record).sort().join(',')!=='after,kind'||!this.pending||!equal(record.after,this.pending.after))throw new CheckpointMismatch();
        this.head=record.after;this.pending=null;
      }else if(record?.kind==='abort'){
        if(Object.keys(record).sort().join(',')!=='before,kind'||!this.pending||!equal(record.before,this.pending.before))throw new CheckpointMismatch();
        this.pending=null;
      }else throw new CheckpointMismatch();
    }
    // Only an incomplete trailing append can be discarded. A complete invalid
    // record fails closed. No later append may be joined onto a torn fragment.
    if(end!==data.length){
      const repair=await open(this.path,'r+');try{await repair.truncate(end);await repair.sync();}finally{await repair.close();}
    }
    this.bytes=end;this.loaded=true;
  }
  async append(record){
    if(this.failed)throw new CheckpointMismatch();
    const data=Buffer.from(line(record));
    try{
      const file=await open(this.path,'a');
      try{
        let offset=0;
        while(offset<data.length){const {bytesWritten}=await file.write(data,offset,data.length-offset);if(!bytesWritten)throw new Error('Checkpoint write failed');offset+=bytesWritten;}
        await file.sync();
      }finally{await file.close();}
      this.bytes+=data.length;
    }catch(error){this.failed=true;throw error;}
  }
  async retireLegacy(){
    if(this.retired)return;
    let original;
    try{original=await open(this.legacyPath,'r');}
    catch(error){if(error.code!=='ENOENT')throw error;}
    if(original){
      await original.close();let marker;
      try{marker=await open(this.legacyPath+'.legacy','r');}
      catch(error){if(error.code!=='ENOENT')throw error;}
      if(marker){await marker.close();throw new CheckpointMismatch();}
      try{await rename(this.legacyPath,this.legacyPath+'.legacy');await this.directorySync();}
      catch(error){this.failed=true;throw error;}
    }
    this.retired=true;
  }
  async verify(actual){
    if(process.platform==='win32')throw new Error('Durable runtime checkpoints require Linux');
    await this.load();
    if(!this.loaded){
      // A completed upgrade cannot silently fall back if its journal is lost.
      let retired;
      try{retired=await open(this.legacyPath+'.legacy','r');}
      catch(error){if(error.code!=='ENOENT')throw error;}
      if(retired){await retired.close();throw new CheckpointMismatch();}
      await this.legacy.verify(actual);this.head=actual;this.pending=null;
      await this.replace();
      this.loaded=true;
    }
    // Complete an interrupted upgrade whose journal was durable before the
    // legacy file was renamed. This must happen before serving any queries.
    await this.retireLegacy();
    if(this.pending){
      if(equal(actual,this.pending.after))await this.finish(actual);
      else if(equal(actual,this.pending.before)){await this.append({kind:'abort',before:actual});this.pending=null;}
      else throw new CheckpointMismatch();
    }
    if(!equal(actual,this.head))throw new CheckpointMismatch();
  }
  async prepare(before,after){
    await this.load();
    if(!this.loaded||this.pending||!equal(before,this.head)||!valid(after)||after.dataset!==before.dataset)throw new CheckpointMismatch();
    if(this.bytes>MAX-4096)await this.replace();
    await this.append({kind:'prepare',before,after});this.pending={before,after};
  }
  async finish(after){
    if(!this.pending||!equal(after,this.pending.after))throw new CheckpointMismatch();
    await this.append({kind:'finish',after});this.head=after;this.pending=null;
  }
}
