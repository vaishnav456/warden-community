// Package main — wireguard.go is intentionally unused.
//
// Warden does not use a VPN mesh. Outbound-only WSS/HTTPS on 443 traverses
// customer-office NAT/firewalls reliably; a UDP WireGuard tunnel would not.
// The security boundary instead comes from pinned TLS (comms.go) plus
// Ed25519-signed, nonce-protected job envelopes (signing.go) verified on
// every request. See warden/md/system-warden-design.md for the full model.
//
// This file is kept only so the historical intent is documented in one
// place — nothing in agent.go calls into it.
package main
