import { request } from 'node:http';
import { readFile } from 'node:fs/promises';

const LIMIT = 8 * 1024 * 1024;
const CHUNK = 1024 * 1024;
const MAX_RECORD = 64 * 1024 * 1024;

export async function sealDocument(box, id, purpose, value) {
  const data = Buffer.from(value, 'utf8');
  if (!data.length || data.length > MAX_RECORD) throw new Error('Invalid record size');
  const count = Math.ceil(data.length / CHUNK);
  const parts = [];
  for (let index=0; index<count; index++) {
    parts.push(await box.seal(id + ':' + index + ':' + count, purpose,
      data.subarray(index * CHUNK, (index+1) * CHUNK).toString('base64')));
  }
  return 'wdb1:' + Buffer.from(JSON.stringify(parts)).toString('base64url');
}
export function cipherParts(value) {
  if (typeof value !== 'string' || !/^wdb1:[A-Za-z0-9_-]+$/.test(value) || value.length > MAX_RECORD * 3) throw new Error('Ciphertext required');
  let parts;
  try { parts = JSON.parse(Buffer.from(value.slice(5), 'base64url').toString('utf8')); }
  catch { throw new Error('Invalid encrypted record'); }
  if (!Array.isArray(parts) || !parts.length || parts.length > MAX_RECORD/CHUNK ||
      parts.some(part => typeof part !== 'string' || !/^enc:v1:[A-Za-z0-9_=-]+$/.test(part) || part.length < 46 || part.length > CHUNK*2)) throw new Error('Invalid encrypted record');
  return parts;
}
export async function unsealDocument(box, id, purpose, value) {
  const parts = cipherParts(value);
  const buffers = [];
  for (let index=0; index<parts.length; index++) {
    const clear = await box.unseal(id + ':' + index + ':' + parts.length, purpose, parts[index]);
    if (typeof clear !== 'string' || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(clear)) throw new Error('Invalid encrypted record');
    const data = Buffer.from(clear, 'base64');
    if (!data.length || data.length > CHUNK || (index<parts.length-1 && data.length !== CHUNK)) throw new Error('Invalid encrypted record');
    buffers.push(data);
  }
  return new TextDecoder('utf-8', {fatal:true}).decode(Buffer.concat(buffers));
}

// Production encryption stays in key custody. This client never receives a key.
export class KeyServiceBox {
  constructor(socketPath, tokenFile) {
    if (!socketPath?.startsWith('/') || !tokenFile?.startsWith('/')) {
      throw new Error('Absolute private key-service paths required');
    }
    this.socketPath = socketPath;
    this.tokenFile = tokenFile;
    this.queues={seal:[],unseal:[]};
  }
  async call(operation, arguments_) {
    const token = (await readFile(this.tokenFile, 'utf8')).trim();
    if (token.length < 32 || !/^[\x21-\x7e]+$/.test(token)) throw new Error('Invalid key-service credential');
    const body = JSON.stringify({operation, arguments: arguments_});
    if (Buffer.byteLength(body) > LIMIT) throw new Error('Key-service request too large');
    return new Promise((resolve, reject) => {
      const req = request({socketPath:this.socketPath, method:'POST', path:'/v1/operate',
        headers:{Authorization:'Bearer ' + token, 'Content-Type':'application/json', 'Content-Length':Buffer.byteLength(body)}}, res => {
        const chunks = []; let length = 0;
        res.on('data', chunk => {
          length += chunk.length;
          if (length > LIMIT * 2) { res.destroy(); reject(new Error('Invalid key-service response')); }
          else chunks.push(chunk);
        });
        res.on('error', () => reject(new Error('Key service unavailable')));
        res.on('end', () => {
          try {
            const value = JSON.parse(Buffer.concat(chunks).toString('utf8'));
            if (res.statusCode !== 200 || !Object.hasOwn(value, 'result')) throw new Error();
            resolve(value.result);
          } catch { reject(new Error('Key service rejected operation')); }
        });
      });
      req.setTimeout(30000, () => req.destroy());
      req.on('error', () => reject(new Error('Key service unavailable')));
      req.end(body);
    });
  }
  seal(id, purpose, value) {
    if(purpose.startsWith('database.')) return this.batch('seal',id,purpose,value);
    return this.call('platform.encrypt_platform_field', {record_id:id, purpose, value});
  }
  unseal(id, purpose, value) {
    if(purpose.startsWith('database.')) return this.batch('unseal',id,purpose,value);
    return this.call('platform.decrypt_platform_field', {record_id:id, purpose, value});
  }
  batch(kind,id,purpose,value) {
    return new Promise((resolve,reject)=>{
      const queue=this.queues[kind];queue.push({record:{record_id:id,purpose,value},resolve,reject});
      if(queue.length===1)setTimeout(()=>this.flush(kind),0);
    });
  }
  async flush(kind) {
    const queue=this.queues[kind];if(!queue.length)return;
    let size=0;const items=[];
    while(queue.length&&items.length<128) {
      const bytes=Buffer.byteLength(JSON.stringify(queue[0].record));
      if(items.length&&size+bytes>6*1024*1024)break;
      size+=bytes;items.push(queue.shift());
    }
    if(queue.length)setTimeout(()=>this.flush(kind),0);
    try {
      const result=await this.call('platform.'+(kind==='seal'?'encrypt':'decrypt')+'_database_batch',{records:items.map(item=>item.record)});
      if(!Array.isArray(result)||result.length!==items.length)throw new Error('Invalid key-service batch response');
      items.forEach((item,index)=>item.resolve(result[index]));
    }catch(error){items.forEach(item=>item.reject(error));}
  }
}

export function rowPurpose(dataset, collection) {
  return 'database.row.v1:' + dataset + ':' + collection;
}
export function manifestPurpose(revision) {
  return 'database.manifest.v1:' + revision;
}
