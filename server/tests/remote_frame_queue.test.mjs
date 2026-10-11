import {test} from 'node:test';
import assert from 'node:assert/strict';
import {RemoteFrameQueue,RemoteFrameRenderer,parseRemoteFrame,remoteViewportSize} from '../static/js/remote_frame_queue.mjs';
const frame=(type,size=10)=>{
  const bytes=new Uint8Array(size);bytes[0]=type;
  if(type===1&&size>=9){const view=new DataView(bytes.buffer,1,8);view.setUint16(4,1,true);view.setUint16(6,1,true);}
  return bytes.buffer;
};
const deferred=()=>{let resolve,reject;const promise=new Promise((yes,no)=>{resolve=yes;reject=no;});return {promise,resolve,reject};};
const bitmap=()=>({closed:0,close(){this.closed++;}});
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
test('renderer skips superseded asynchronous deltas and closes every bitmap',async()=>{
  const first=frame(0),old=frame(1),oldDelta=frame(1),latest=frame(0),delta=frame(1),pending=deferred();
  const images=new Map([first,old,latest,delta].map(packet=>[packet,bitmap()])),decoded=[],drawn=[];let count=0;
  const renderer=new RemoteFrameRenderer({
    decode:packet=>{decoded.push(packet);return packet===old?pending.promise:Promise.resolve(images.get(packet));},
    draw:image=>drawn.push(image),onFrame:()=>count++,
  });
  await renderer.push(first);const work=renderer.push(old);renderer.push(oldDelta);renderer.push(latest);renderer.push(delta);
  pending.resolve(images.get(old));await work;
  assert.deepEqual(decoded,[first,old,latest,delta]);assert.deepEqual(drawn,[images.get(first),images.get(latest),images.get(delta)]);
  assert.equal(count,3);assert([...images.values()].every(image=>image.closed===1));assert.equal(renderer.queue.bytes,0);
});
test('a continuous full-frame source makes progress even when arrival outruns decoding',async()=>{
  const packets=[frame(0),frame(0),frame(0)],images=packets.map(()=>bitmap()),
    pending=packets.map(()=>deferred()),started=packets.map(()=>deferred()),drawn=[];
  const renderer=new RemoteFrameRenderer({decode:packet=>{const index=packets.indexOf(packet);started[index].resolve();return pending[index].promise;},
    draw:image=>drawn.push(image)});
  const work=renderer.push(packets[0]);renderer.push(packets[1]);pending[0].resolve(images[0]);await started[1].promise;
  assert.deepEqual(drawn,[images[0]],'first image was starved by a newer queued full');
  renderer.push(packets[2]);pending[1].resolve(images[1]);await started[2].promise;
  assert.deepEqual(drawn,[images[0],images[1]],'continuous full frames stopped visible progress');
  pending[2].resolve(images[2]);await work;assert.deepEqual(drawn,images);assert(images.every(image=>image.closed===1));
});
test('obsolete decode errors preserve a newer full frame and its delta chain',async()=>{
  const old=frame(0),latest=frame(0),delta=frame(1),pending=deferred(),drawn=[],errors=[];
  const images=new Map([latest,delta].map(packet=>[packet,bitmap()]));
  const renderer=new RemoteFrameRenderer({decode:packet=>packet===old?pending.promise:Promise.resolve(images.get(packet)),
    draw:image=>drawn.push(image),onError:error=>errors.push(error)});
  const work=renderer.push(old);renderer.push(latest);renderer.push(delta);pending.reject(new Error('old JPEG failed'));await work;
  assert.deepEqual(drawn,[images.get(latest),images.get(delta)]);assert.equal(errors.length,0);
  assert.equal(renderer.queue.awaitingFull,false);assert([...images.values()].every(image=>image.closed===1));
});
test('a current render failure closes its bitmap and requires a fresh full baseline',async()=>{
  const first=frame(0),bad=frame(1),following=frame(1),latest=frame(0),pending=deferred(),drawn=[],errors=[];
  const images=new Map([first,bad,latest].map(packet=>[packet,bitmap()]));
  const renderer=new RemoteFrameRenderer({decode:packet=>packet===bad?pending.promise:Promise.resolve(images.get(packet)),
    draw:image=>{if(image===images.get(bad))throw new Error('drawing failed');drawn.push(image);},
    onError:error=>errors.push(error)});
  await renderer.push(first);const work=renderer.push(bad);renderer.push(following);pending.resolve(images.get(bad));await work;
  assert.equal(renderer.queue.awaitingFull,true);assert.equal(renderer.queue.bytes,0);assert.equal(errors.length,1);
  await renderer.push(following);assert.deepEqual(drawn,[images.get(first)]);
  await renderer.push(latest);assert.deepEqual(drawn,[images.get(first),images.get(latest)]);
  assert([...images.values()].every(image=>image.closed===1));
});
test('stream reset prevents an in-flight frame from painting across a resize or new init',async()=>{
  const old=frame(0),latest=frame(0),pending=deferred(),oldImage=bitmap(),newImage=bitmap(),drawn=[];
  let dimensions=[1024,768];
  const renderer=new RemoteFrameRenderer({decode:packet=>packet===old?pending.promise:Promise.resolve(newImage),
    draw:image=>drawn.push([image,...dimensions])});
  const work=renderer.push(old);renderer.reset();dimensions=[1920,1080];renderer.push(frame(1));
  pending.resolve(oldImage);await work;assert.equal(drawn.length,0);assert.equal(oldImage.closed,1);
  await renderer.push(latest);assert.deepEqual(drawn,[[newImage,1920,1080]]);assert.equal(newImage.closed,1);
});
test('overflow invalidates an in-flight baseline until the next full frame',async()=>{
  const old=frame(0),latest=frame(0),pending=deferred(),oldImage=bitmap(),newImage=bitmap(),drawn=[];
  const renderer=new RemoteFrameRenderer({queue:new RemoteFrameQueue(2),
    decode:packet=>packet===old?pending.promise:Promise.resolve(newImage),draw:image=>drawn.push(image)});
  const work=renderer.push(old);renderer.push(frame(1));renderer.push(frame(1));renderer.push(frame(1));
  pending.resolve(oldImage);await work;assert.equal(drawn.length,0);assert.equal(renderer.queue.awaitingFull,true);
  assert.equal(oldImage.closed,1);await renderer.push(latest);assert.deepEqual(drawn,[newImage]);assert.equal(newImage.closed,1);
});
test('frame headers parse directly from native-coordinate binary packets',()=>{
  const packet=frame(1),view=new DataView(packet,1,8);
  [10,20,50,25].forEach((value,index)=>view.setUint16(index*2,value,true));
  assert.deepEqual(parseRemoteFrame(packet),{type:1,offset:9,x:10,y:20,w:50,h:25});
  assert.deepEqual(parseRemoteFrame(frame(0)),{type:0,offset:1});
  for(const invalid of [new ArrayBuffer(0),frame(2),frame(1,9),{},null])assert.throws(()=>parseRemoteFrame(invalid));
  view.setUint16(4,0,true);assert.throws(()=>parseRemoteFrame(packet));
});
test('viewport requests follow fitted canvas dimensions in wide-short and tall-narrow windows',()=>{
  assert.deepEqual(remoteViewportSize(875,656,1,1024,768),{w:875,h:656});
  assert.deepEqual(remoteViewportSize(600,338,1,1920,1080),{w:600,h:338});
  assert.deepEqual(remoteViewportSize(875,656,2,1024,768),{w:1024,h:768});
  assert.deepEqual(remoteViewportSize(1023.9,767.9,1,1024,768),{w:1023,h:767});
});
test('actual and stretched viewport requests retain native input coordinates and bounded resolution',()=>{
  assert.deepEqual(remoteViewportSize(1024,768,1,1024,768),{w:1024,h:768});
  assert.deepEqual(remoteViewportSize(1024,768,2,1024,768),{w:1024,h:768});
  assert.deepEqual(remoteViewportSize(1200,600,1,1024,768),{w:800,h:600});
  assert.deepEqual(remoteViewportSize(600,1000,1,1024,768),{w:600,h:450});
  assert.deepEqual(remoteViewportSize(0.1,0.1,1,1024,768),{w:1,h:1});
});
test('viewport requests reject hidden or invalid bounds and use a safe DPR fallback',()=>{
  for(const dpr of [undefined,NaN,Infinity,0,-1,'2'])assert.deepEqual(remoteViewportSize(800,600,dpr,1024,768),{w:800,h:600});
  for(const bounds of [[0,600,1024,768],[800,-1,1024,768],[NaN,600,1024,768],
    [800,Infinity,1024,768],[800,600,0,768],[800,600,1024,0.5]])assert.equal(remoteViewportSize(bounds[0],bounds[1],1,bounds[2],bounds[3]),null);
});
