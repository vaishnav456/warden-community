import {test} from 'node:test';
import assert from 'node:assert/strict';
import {EnvelopeRegistry} from '../replay.mjs';
test('replay retention rejects duplicates, bounds memory and expires independently of wall-clock changes',()=>{
  let now=0;const registry=new EnvelopeRegistry({limit:2,lifetime:60,clock:()=>now});
  registry.accept('first');now=10;registry.accept('second');
  assert.throws(()=>registry.accept('first'),/Replayed/);
  assert.throws(()=>registry.accept('third'),error=>error.status===503);
  now=60;registry.accept('third');assert.equal(registry.entries.size,2);
  assert.throws(()=>registry.accept('second'),/Replayed/);
  now=70;registry.accept('first');assert.equal(registry.entries.size,2);
});
test('large valid registry accepts new envelopes without walking its unexpired entries',()=>{
  const registry=new EnvelopeRegistry();for(let item=0;item<20000;item++)registry.accept(String(item));
  let visited=0;const iterator=registry.entries[Symbol.iterator].bind(registry.entries);
  registry.entries[Symbol.iterator]=function*(){for(const entry of iterator()){visited++;yield entry;}};
  registry.accept('new');assert.equal(visited,1);assert.equal(registry.entries.size,20001);
});
