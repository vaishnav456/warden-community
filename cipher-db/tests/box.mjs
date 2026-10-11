// Synthetic fixture keys only. Never used by the application runtime.
import {randomBytes,createCipheriv,createDecipheriv} from 'node:crypto';
export class Box {
  key=randomBytes(32);
  async seal(id,purpose,value){const nonce=randomBytes(12),c=createCipheriv('aes-256-gcm',this.key,nonce);c.setAAD(Buffer.from(JSON.stringify([purpose,id])));
    const data=Buffer.concat([c.update(value,'utf8'),c.final()]);return 'enc:v1:'+Buffer.concat([nonce,c.getAuthTag(),data]).toString('base64url');}
  async unseal(id,purpose,value){const b=Buffer.from(value.slice(7),'base64url'),c=createDecipheriv('aes-256-gcm',this.key,b.subarray(0,12));
    c.setAAD(Buffer.from(JSON.stringify([purpose,id])));c.setAuthTag(b.subarray(12,28));return Buffer.concat([c.update(b.subarray(28)),c.final()]).toString('utf8');}
}
