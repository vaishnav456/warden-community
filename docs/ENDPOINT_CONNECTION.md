# Endpoint connection lifecycle

Warden Community uses outbound HTTPS/WebSocket connections from each endpoint;
the endpoint does not need an inbound management port.

1. An organization administrator creates an enrollment profile or token and
   downloads the matching installer package.
2. The Agent generates device key material locally and submits its token,
   hardware identity, installation identity, and certificate request over TLS.
3. The server validates the one-time enrollment rules, binds the endpoint to
   the deployment's single organization, ignores certificate names requested
   by the device, and returns endpoint credentials plus a short-lived device
   certificate.
4. The Agent stores secrets using the operating system's protected storage,
   sends authenticated heartbeats and inventory, and renews its device
   certificate before expiry.
5. Administrators create jobs in the console. The server signs each command;
   the Agent claims only jobs for its endpoint, verifies the signature and
   freshness, executes an allowlisted operation, and uploads a bounded result.
6. Remote support uses an authenticated WebSocket session. Attended sessions
   fail closed until the endpoint user approves; capabilities and session state
   are checked again by the relay.
7. Warden Home grants are signed, short-lived, and bound to the organization,
   endpoint, user/identity, space, permission, and selected node. File bytes
   travel directly between the endpoint and Home Node; the control plane only
   introduces peers and never silently relays file contents.

Removing an endpoint invalidates its server credentials immediately. An Agent
left installed after portal removal remains disconnected and must use a new
enrollment token to return. Certificate rotation does not require a new token
while the endpoint record and credentials are still active.

The automated suite covers single-organization authorization, token/profile
matching, re-enrollment, certificate identity, signed jobs and leases,
heartbeat state, WebSocket consent/capabilities, Warden Home grants and P2P
binding, retirement, and update package validation. A release should also run
an actual Windows enrollment and signed job on a disposable VM because a
cross-compile cannot execute Windows service, Credential Provider, DPAPI,
BitLocker, firewall, or desktop-capture behavior.
