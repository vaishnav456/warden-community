# Adaptive server load control

This is single-process workload admission, not multi-server routing. Keep one
Gunicorn worker while relay registries and schedulers remain process-local.

Every second the relay samples container CPU usage (normalized to its CPU quota),
container memory usage, relay event-loop delay and recent HTTP response duration.
Unlimited-memory Linux hosts use host available-memory pressure instead. If
cgroup counters are unavailable, HTTP duration and relay delay still participate.

Three consecutive high-pressure samples pause new remote and Home relay pairs.
Memory pressure above 95% pauses immediately. Ten consecutive healthy samples
resume admission. State transitions are logged through warden.load_control.
Normal thresholds are CPU/memory 85%, relay delay 150 ms or HTTP duration 1 s;
recovery requires CPU below 65%, memory below 80%, relay delay below 75 ms
and recent HTTP duration below 500 ms. These defaults are
conservative starting points, not a guaranteed endpoint/session capacity.

Existing pairs can attach their second authenticated peer even while busy.
Active sessions, authenticated heartbeats, consent and job results are not
rejected by this controller. Routine metric history is sampled at most once
per endpoint per minute while busy; current status and command delivery continue.
The metric tracking cache is bounded to 10,000 entries.

There is no fixed per-tenant remote allowance: tenants borrow unused capacity.
Near pressure, the largest existing tenant share yields new admissions when
multiple tenants are using the relay. Emergency registry bounds (256 pairs per
relay type), 8 MiB messages and bounded receive queues remain memory safeguards.
HTTP remote creation returns 503 with Retry-After: 15; WebSocket admission returns
1013. Clients must retry later rather than spin reconnect loops.

This does not provide HTTP queue ordering, distributed fairness, guaranteed
bandwidth, job scheduling priorities, or hardware video encoding. It protects
capacity by shedding new relay work and reducing background metric writes.
Internet link saturation without CPU, memory or latency pressure is not directly
measured. Validate thresholds under representative workloads before production.

Agent startup heartbeats use a stable endpoint-ID-derived phase across 30 seconds
to avoid fleet restart bursts. Steady heartbeat cadence is unchanged. Source
version changes do not publish/install an agent automatically.
