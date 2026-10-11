import {createHash} from 'node:crypto';
const hash=value=>createHash('sha256').update(value).digest('hex');
const MOD=1n<<256n;
export const member=(id,payload)=>BigInt('0x'+hash(id+':'+hash(payload)));
export const hex=value=>((value%MOD+MOD)%MOD).toString(16).padStart(64,'0');
export function integrity(rows){let sum=0n;for(const [id,payload] of rows)sum+=member(id,payload);return hex(sum);}
