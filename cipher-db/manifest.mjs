import {deflateRaw,inflateRaw} from 'node:zlib';
import {promisify} from 'node:util';

const compress=promisify(deflateRaw),expand=promisify(inflateRaw);
const MAX=64*1024*1024,ENCODING='warden.manifest.deflate.v1';

// Only private schema/checkpoint metadata is compressed, before authenticated
// encryption. Rows and request/response envelopes keep their original format.
export async function encodeManifest(manifest){
  const raw=Buffer.from(JSON.stringify(manifest));
  if(!raw.length||raw.length>MAX)throw new Error('Invalid manifest size');
  const data=await compress(raw,{level:1});
  const wrapped=JSON.stringify({encoding:ENCODING,bytes:raw.length,data:data.toString('base64')});
  return Buffer.byteLength(wrapped)<raw.length?wrapped:raw.toString('utf8');
}
export async function decodeManifest(text){
  const value=JSON.parse(text);
  if(value?.encoding===undefined)return value;
  if(Object.keys(value).sort().join(',')!=='bytes,data,encoding'||value.encoding!==ENCODING||
    !Number.isSafeInteger(value.bytes)||value.bytes<1||value.bytes>MAX||typeof value.data!=='string'||
    value.data.length>MAX*2||! /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value.data))throw new Error('Invalid compressed manifest');
  const raw=await expand(Buffer.from(value.data,'base64'),{maxOutputLength:value.bytes});
  if(raw.length!==value.bytes)throw new Error('Invalid manifest length');
  return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(raw));
}
