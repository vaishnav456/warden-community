# Agent mutual TLS deployment

Warden can require a trusted reverse proxy to validate client certificates before agent requests reach the application. This is an additional boundary; it does not replace Warden's device certificates, signed commands, organization authorization, or TLS validation.

## Safe deployment conditions

Set `REQUIRE_CLIENT_CERT=true` only when all of these conditions are true:

1. The configured proxy validates client certificates for the Warden agent hostname.
2. The proxy forwards a verified certificate fingerprint in the header expected by Warden.
3. Direct access to the origin is blocked at the network layer.
4. `TRUST_CLOUDFLARE=true` is used only when Cloudflare is the sole trusted ingress; another proxy requires equivalent, reviewed integration rather than accepting client-supplied headers.
5. Enrollment and certificate-rotation recovery have been tested before enforcement.

If an attacker can reach the origin directly, they can forge ordinary HTTP headers. Warden therefore fails closed when client-certificate enforcement is enabled without the trusted-proxy configuration.

## Credentials

Cloudflare API tokens and zone identifiers are deployment secrets. Store them outside Git with the minimum required permissions. Never include them in images, source, logs, support bundles, or example configuration.

Provider dashboard steps and API fields change over time. Follow the current provider documentation and verify the resulting request headers at a non-production origin before rollout.
