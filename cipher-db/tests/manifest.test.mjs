import {test} from 'node:test';
import assert from 'node:assert/strict';
import {encodeManifest,decodeManifest} from '../manifest.mjs';

test('compressed manifests preserve schema bytes and accept legacy manifests',async()=>{
  const manifest={v:1,schema:('CREATE TABLE "秘密" (id uuid PRIMARY KEY);\n').repeat(12000),tables:[]};
  const encoded=await encodeManifest(manifest);
  assert(encoded.length<JSON.stringify(manifest).length/10);
  assert.deepEqual(await decodeManifest(encoded),manifest);
  assert.deepEqual(await decodeManifest(JSON.stringify(manifest)),manifest);
});
test('manifest decompression rejects malformed data and expansion beyond authenticated bounds',async()=>{
  const encoded=JSON.parse(await encodeManifest({v:1,schema:'abc'.repeat(100000)}));
  for(const change of [{bytes:8},{bytes:64*1024*1024+1},{data:'not base64!'},{encoding:'unknown'},{extra:true}]){
    await assert.rejects(decodeManifest(JSON.stringify({...encoded,...change})));
  }
});
