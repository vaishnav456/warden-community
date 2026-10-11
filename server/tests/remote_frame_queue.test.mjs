import {test} from 'node:test';
import assert from 'node:assert/strict';
import {RemoteFrameQueue} from '../static/js/remote_frame_queue.mjs';
const frame=(type,size=10)=>{const bytes=new Uint8Array(size);bytes[0]=type;return bytes.buffer;};
test('new full snapshot replaces queued older snapshots and deltas',()=>{
  const q=new RemoteFrameQueue(),full=frame(0),delta=frame(1),latest=frame(0);
  q.push(full);q.push(delta);q.push(latest);
  assert.equal(q.length,1);assert.equal(q.take(),latest);assert.equal(q.bytes,0);
});
test('deltas after the latest snapshot retain their original order',()=>{
  const q=new RemoteFrameQueue(),full=frame(0),first=frame(1),second=frame(1);
  [full,first,second].forEach(f=>assert.equal(q.push(f),true));
  assert.deepEqual([q.take(),q.take(),q.take()],[full,first,second]);
});
test('overflow drops delta chains until a complete baseline arrives',()=>{
  const q=new RemoteFrameQueue(2),full=frame(0);
  q.push(frame(0));q.push(frame(1));assert.equal(q.push(frame(1)),false);
  assert.equal(q.length,0);assert.equal(q.bytes,0);assert.equal(q.awaitingFull,true);
  assert.equal(q.push(frame(1)),false);assert.equal(q.push(full),true);
  assert.equal(q.awaitingFull,false);assert.equal(q.take(),full);
});
test('new and reset streams require a complete baseline before deltas',()=>{
  const q=new RemoteFrameQueue();assert.equal(q.push(frame(1)),false);
  assert.equal(q.push(frame(0)),true);q.take();assert.equal(q.push(frame(1)),true);
  q.desynchronize();assert.equal(q.push(frame(1)),false);assert.equal(q.length,0);
  assert.equal(q.push(frame(0)),true);
});
test('byte bound and malformed packets require resynchronization',()=>{
  const q=new RemoteFrameQueue(12,20);
  q.push(frame(0,15));assert.equal(q.push(frame(1,10)),false);
  assert.equal(q.awaitingFull,true);assert.equal(q.push(frame(0,21)),false);
  assert.equal(q.push(frame(2)),false);assert.equal(q.push(frame(1,2)),false);
  assert.equal(q.push(new ArrayBuffer(0)),false);
  assert.equal(q.push(frame(0)),true);assert.equal(q.bytes,10);
});
test('decode failure discards subsequent deltas and releases queued bytes',()=>{
  const q=new RemoteFrameQueue();q.push(frame(0));q.push(frame(1));q.take();
  q.desynchronize();assert.equal(q.bytes,0);assert.equal(q.push(frame(1)),false);
  assert.equal(q.push(frame(0)),true);
});
