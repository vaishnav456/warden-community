"""Fixed numeric diagnostics from an authenticated remote agent; no contents."""
import math

TIMING_FIELDS = ('dxgi_wait', 'dxgi_readback', 'gdi_capture', 'jpeg_encode',
                 'pipe_write', 'ws_writer_wait', 'ws_write', 'input_queue',
                 'input_pipe_write', 'input_pipe_queue', 'input_dispatch')
COUNTER_FIELDS = ('full_frames', 'partial_frames', 'dxgi_frames', 'gdi_frames',
                  'replay_frames', 'dxgi_idle', 'dxgi_accumulated')
DIMENSION_FIELDS = ('native_w', 'native_h', 'encoded_w', 'encoded_h')


def _number(value, maximum, integer=False):
    if type(value) not in (int, float) or (integer and type(value) is not int):
        return False
    try:
        return 0 <= value <= maximum and math.isfinite(value)
    except OverflowError:
        return False


def _window(value):
    fields = set(COUNTER_FIELDS + DIMENSION_FIELDS + ('window_ms', 'input_queue_max', 'encoded_bytes', 'timings'))
    if not isinstance(value, dict) or set(value) != fields:
        return None
    for names, maximum, integer in ((COUNTER_FIELDS, 1000000, True), (DIMENSION_FIELDS, 16384, True),
                                    (('window_ms',), 60000, False), (('input_queue_max',), 128, True),
                                    (('encoded_bytes',), 1073741824, True)):
        if any(not _number(value[name], maximum, integer) for name in names):
            return None
    timings = value['timings']
    if not isinstance(timings, dict) or set(timings) != set(TIMING_FIELDS):
        return None
    result = {key: value[key] for key in fields if key != 'timings'}
    result['timings'] = {}
    for name in TIMING_FIELDS:
        timing = timings[name]
        if not isinstance(timing, dict) or set(timing) != {'samples', 'mean_ms', 'max_ms'} \
                or not _number(timing['samples'], 1000000, True) \
                or not _number(timing['mean_ms'], 60000) or not _number(timing['max_ms'], 60000) \
                or timing['mean_ms'] > timing['max_ms'] \
                or (timing['samples'] == 0 and (timing['mean_ms'] != 0 or timing['max_ms'] != 0)):
            return None
        result['timings'][name] = dict(timing)
    return result


def validate_agent_performance(value):
    if not isinstance(value, dict) or value.get('type') != 'remote_agent_performance' \
            or type(value.get('version')) is not int or value['version'] != 1 \
            or set(value) not in ({'type', 'version', 'service'}, {'type', 'version', 'service', 'helper', 'helper_age_ms'}):
        return None
    service = _window(value['service'])
    if service is None:
        return None
    result = {'type': 'remote_agent_performance', 'version': 1, 'service': service}
    if 'helper' in value:
        helper = _window(value['helper'])
        if helper is None or not _number(value['helper_age_ms'], 60000):
            return None
        result.update(helper=helper, helper_age_ms=value['helper_age_ms'])
    return result
