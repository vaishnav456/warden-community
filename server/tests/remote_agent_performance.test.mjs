import assert from 'node:assert/strict';
import test from 'node:test';
import {validateRemoteAgentPerformance, remoteAgentPerformanceText} from '../static/js/remote_agent_performance.mjs';

const names = ['dxgi_wait','dxgi_readback','gdi_capture','jpeg_encode','pipe_write','ws_writer_wait','ws_write','input_queue','input_pipe_write','input_pipe_queue','input_dispatch'];
function window() {
  return {window_ms:5000,native_w:1920,native_h:1080,encoded_w:1280,encoded_h:720,input_queue_max:3,
    full_frames:2,partial_frames:10,dxgi_frames:12,gdi_frames:0,replay_frames:0,dxgi_idle:1,dxgi_accumulated:0,encoded_bytes:4096,
    timings:Object.fromEntries(names.map(name=>[name,{samples:1,mean_ms:2,max_ms:3}]))};
}
const report = () => ({type:'remote_agent_performance',version:1,service:window(),helper:window(),helper_age_ms:10});

test('bounded valid report survives and has independent nested timing values', () => {
  const input=report(), result=validateRemoteAgentPerformance(input);
  assert.deepEqual(result,input);
  input.service.timings.ws_write.max_ms=5000;
  assert.equal(result.service.timings.ws_write.max_ms,3);
  assert.ok(validateRemoteAgentPerformance({type:'remote_agent_performance',version:1,service:window()}));
});
test('wrong types, nonfinite values, integer overflow and inconsistent timings are rejected', () => {
  for (const value of [true,'contents',-1,NaN,Infinity,1e100,1.5]) {
    const input=report();input.service.input_queue_max=value;
    assert.equal(validateRemoteAgentPerformance(input),null);
  }
  for (const [key,value] of [['native_w',16385],['full_frames',1e6+1],['encoded_bytes',1073741825],['window_ms',60001]]) {
    const input=report();input.helper[key]=value;
    assert.equal(validateRemoteAgentPerformance(input),null);
  }
  for (const change of [{samples:0},{mean_ms:4},{max_ms:Infinity},{samples:true},{secret:'contents'}]) {
    const input=report();Object.assign(input.service.timings.ws_write,change);
    assert.equal(validateRemoteAgentPerformance(input),null);
  }
});
test('unknown fields, missing helper age and unsupported versions do not enter text', () => {
  const invalid=report();invalid.service.coordinates='secret';
  assert.equal(validateRemoteAgentPerformance(invalid),null);
  assert.equal(remoteAgentPerformanceText(invalid),'');
  for (const input of [[],null,{...report(),version:2},{...report(),helper_age_ms:NaN},{...report(),helper_age_ms:60001}]) {
    assert.equal(validateRemoteAgentPerformance(input),null);
  }
  const missing=report();delete missing.helper_age_ms;
  assert.equal(validateRemoteAgentPerformance(missing),null);
});
test('text separates input, upload, capture and idle wait rather than reporting them as input RTT', () => {
  const text=remoteAgentPerformanceText(report());
  assert.match(text,/input queue 2 ms average\/3 ms maximum/);
  assert.match(text,/Agent upload 2 ms/);
  assert.match(text,/encoded 1280×720/);
  assert.match(text,/acquisition wait .*includes idle time/);
  assert.doesNotMatch(text,/input RTT/);
  assert.match(remoteAgentPerformanceText({...report(),helper_age_ms:16000}),/Fresh capture timing is pending/);
});
