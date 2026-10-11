const timingFields = ['dxgi_wait', 'dxgi_readback', 'gdi_capture', 'jpeg_encode', 'pipe_write',
  'ws_writer_wait', 'ws_write', 'input_queue', 'input_pipe_write', 'input_pipe_queue', 'input_dispatch'];
const counterFields = ['full_frames', 'partial_frames', 'dxgi_frames', 'gdi_frames',
  'replay_frames', 'dxgi_idle', 'dxgi_accumulated'];
const dimensionFields = ['native_w', 'native_h', 'encoded_w', 'encoded_h'];
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const keys = (value, names) => object(value) && Object.keys(value).length === names.length
  && names.every(name => Object.hasOwn(value, name));
const number = (value, maximum, integer = false) => typeof value === 'number' && Number.isFinite(value)
  && value >= 0 && value <= maximum && (!integer || Number.isInteger(value));

function windowReport(value) {
  const fields = [...counterFields, ...dimensionFields, 'window_ms', 'input_queue_max', 'encoded_bytes', 'timings'];
  if (!keys(value, fields)) return null;
  for (const [names, maximum, integer] of [[counterFields, 1e6, true], [dimensionFields, 16384, true],
    [['window_ms'], 60000, false], [['input_queue_max'], 128, true], [['encoded_bytes'], 1073741824, true]]) {
    if (names.some(name => !number(value[name], maximum, integer))) return null;
  }
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
  if (!object(value) || value.type !== 'remote_agent_performance' || value.version !== 1
    || !(keys(value, ['type', 'version', 'service'])
      || keys(value, ['type', 'version', 'service', 'helper', 'helper_age_ms']))) return null;
  const service = windowReport(value.service);
  if (!service) return null;
  const result = {type: 'remote_agent_performance', version: 1, service};
  if (Object.hasOwn(value, 'helper')) {
    const helper = windowReport(value.helper);
    if (!helper || !number(value.helper_age_ms, 60000)) return null;
    Object.assign(result, {helper, helper_age_ms: value.helper_age_ms});
  }
  return result;
}

export function remoteAgentPerformanceText(value) {
  const report = validateRemoteAgentPerformance(value);
  if (!report) return '';
  const timing = (window, name) => {
    const sample = window.timings[name];
    return sample.samples ? `${Math.round(sample.mean_ms)} ms average/${Math.round(sample.max_ms)} ms maximum` : 'no samples';
  };
  let text = `Agent upload ${timing(report.service, 'ws_write')}; upload writer wait ${timing(report.service, 'ws_writer_wait')}; input queue ${timing(report.service, 'input_queue')} (maximum ${report.service.input_queue_max} events); input pipe ${timing(report.service, 'input_pipe_write')}.`;
  if (report.helper && report.helper_age_ms <= 15000) {
    const helper = report.helper;
    text += ` Capture frames: DXGI ${helper.dxgi_frames}, GDI ${helper.gdi_frames}; encoded ${helper.encoded_w}×${helper.encoded_h}. Readback ${timing(helper, 'dxgi_readback')}; GDI capture ${timing(helper, 'gdi_capture')}; JPEG ${timing(helper, 'jpeg_encode')}; output pipe ${timing(helper, 'pipe_write')}; input pipe transit ${timing(helper, 'input_pipe_queue')} (includes write; coarse host timer); input dispatch ${timing(helper, 'input_dispatch')}. DXGI acquisition wait ${timing(helper, 'dxgi_wait')} includes idle time.`;
  } else {
    text += ' Fresh capture timing is pending.';
  }
  return text;
}
