const timingFields = ['dxgi_wait', 'dxgi_readback', 'gdi_capture', 'jpeg_encode', 'pipe_write',
  'ws_writer_wait', 'ws_write', 'input_queue', 'input_pipe_write', 'input_pipe_queue', 'input_dispatch'];
const counterFields = ['full_frames', 'partial_frames', 'dxgi_frames', 'gdi_frames',
  'replay_frames', 'dxgi_idle', 'dxgi_accumulated'];
const dimensionFields = ['native_w', 'native_h', 'encoded_w', 'encoded_h'];
const inputOutcomeFields = ['input_attempts', 'input_accepted', 'input_rejected'];
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const keys = (value, names) => object(value) && Object.keys(value).length === names.length
  && names.every(name => Object.hasOwn(value, name));
const number = (value, maximum, integer = false) => typeof value === 'number' && Number.isFinite(value)
  && value >= 0 && value <= maximum && (!integer || Number.isInteger(value));

function windowReport(value, version) {
  const counters = [...counterFields, ...(version === 2 ? inputOutcomeFields : [])];
  const fields = [...counters, ...dimensionFields, 'window_ms', 'input_queue_max', 'encoded_bytes', 'timings'];
  if (!keys(value, fields)) return null;
  for (const [names, maximum, integer] of [[counters, 1e6, true], [dimensionFields, 16384, true],
    [['window_ms'], 60000, false], [['input_queue_max'], 128, true], [['encoded_bytes'], 1073741824, true]]) {
    if (names.some(name => !number(value[name], maximum, integer))) return null;
  }
  if (version === 2 && value.input_attempts !== value.input_accepted + value.input_rejected) return null;
  if (!keys(value.timings, timingFields)) return null;
  const result = Object.fromEntries(fields.filter(name => name !== 'timings').map(name => [name, value[name]]));
  result.timings = {};
  for (const name of timingFields) {
    const timing = value.timings[name];
    if (!keys(timing, ['samples', 'mean_ms', 'max_ms']) || !number(timing.samples, 1e6, true)
      || !number(timing.mean_ms, 60000) || !number(timing.max_ms, 60000) || timing.mean_ms > timing.max_ms
      || (timing.samples === 0 && (timing.mean_ms !== 0 || timing.max_ms !== 0))) return null;
    result.timings[name] = {samples: timing.samples, mean_ms: timing.mean_ms, max_ms: timing.max_ms};
  }
  return result;
}

export function validateRemoteAgentPerformance(value) {
  if (!object(value) || value.type !== 'remote_agent_performance' || ![1, 2].includes(value.version)
    || !(keys(value, ['type', 'version', 'service'])
      || keys(value, ['type', 'version', 'service', 'helper', 'helper_age_ms']))) return null;
  const service = windowReport(value.service, value.version);
  if (!service) return null;
  const result = {type: 'remote_agent_performance', version: value.version, service};
  if (Object.hasOwn(value, 'helper')) {
    const helper = windowReport(value.helper, value.version);
    if (!helper || !number(value.helper_age_ms, 60000)) return null;
    Object.assign(result, {helper, helper_age_ms: value.helper_age_ms});
  }
  return result;
}

export function remoteAgentInputNotice(value) {
  const report = validateRemoteAgentPerformance(value);
  return report?.version === 2 && report.helper && report.helper_age_ms <= 15000
    && report.helper.input_rejected > 0 ? 'Windows rejected remote input.' : '';
}

export function remoteAgentPerformanceText(value) {
  const report = validateRemoteAgentPerformance(value);
  if (!report) return '';
  const timing = (window, name) => {
    const sample = window.timings[name];
    return sample.samples ? `${Math.round(sample.mean_ms)} ms average/${Math.round(sample.max_ms)} ms maximum` : 'no samples';
  };
  const seconds = window => (window.window_ms / 1000).toFixed(1);
  let text = `Agent sent ${report.service.full_frames + report.service.partial_frames} frames in ${seconds(report.service)} seconds. Agent upload ${timing(report.service, 'ws_write')}; upload writer wait ${timing(report.service, 'ws_writer_wait')}; input queue ${timing(report.service, 'input_queue')} (${report.service.timings.input_queue.samples} samples, maximum ${report.service.input_queue_max} queued events); input pipe ${timing(report.service, 'input_pipe_write')}.`;
  if (report.helper && report.helper_age_ms <= 15000) {
    const helper = report.helper;
    const outcomes = report.version === 2
      ? `${helper.input_attempts} native input attempts: Windows accepted ${helper.input_accepted}, rejected ${helper.input_rejected}; acceptance does not prove an application responded`
      : `${helper.timings.input_dispatch.samples} attempts; Windows acceptance is not measured`;
    text += ` Capture window ${seconds(helper)} seconds, received ${Math.round(report.helper_age_ms)} ms before the service report; windows can differ. Capture frames: DXGI ${helper.dxgi_frames} (${helper.replay_frames} repeated snapshots), GDI ${helper.gdi_frames}; encoded ${helper.encoded_w}×${helper.encoded_h}. DXGI idle acquisitions ${helper.dxgi_idle}; readback attempts ${helper.timings.dxgi_readback.samples}. Readback ${timing(helper, 'dxgi_readback')}; GDI capture ${timing(helper, 'gdi_capture')}; JPEG ${timing(helper, 'jpeg_encode')}; output pipe ${timing(helper, 'pipe_write')}; input pipe transit ${timing(helper, 'input_pipe_queue')} (includes write; coarse host timer); input dispatch ${timing(helper, 'input_dispatch')} (${outcomes}). DXGI acquisition wait ${timing(helper, 'dxgi_wait')} includes idle time.`;
  } else {
    text += ' Fresh capture timing is pending.';
  }
  return text;
}
