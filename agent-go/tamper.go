package main

// tamper.go — self-protection for the installed agent.
//
// Locks the WardenAgent Windows service and its data directory so a local
// operator (or malware) can't stop/delete it via services.msc, `net stop`,
// `sc delete`, or deleting the folder. The only sanctioned removal path is a
// server-approved, Ed25519-signed UNINSTALL_AGENT job (dual-approval gated,
// see server/routes/endpoints.py) — handled here in performSelfRemoval() and
// via `warden-agent.exe uninstall` in main.go, which fetches and verifies
// that exact job before calling it.
//
// Caveat: this raises the bar against casual removal; it is not
// cryptographically unbypassable. A local account with
// SeTakeOwnershipPrivilege can still eventually reassign ownership of the
// service registry key or data directory by hand. True tamper-proofing
// against a hostile local Administrator needs a kernel-mode filter driver,
// out of scope for a user-mode agent.

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Deny SERVICE_STOP, SERVICE_PAUSE_CONTINUE, DELETE, WRITE_DAC to both
// Administrators (BA) and Authenticated Users (AU); full control only to
// Local System (SY).
//
// Two things beyond the plain DENY/ALLOW split are required for this to
// actually hold:
//
//  1. Owner is pinned to SYSTEM ("O:SYG:SY"). Without it, the object keeps
//     whatever owner `sc create` assigned at install time — typically the
//     installing admin's Administrators (BA) group — and an object's owner
//     always implicitly has READ_CONTROL + WRITE_DAC no matter what the DACL
//     says. That implicit WRITE_DAC lets any BA member call `sc sdset` to
//     reset this very ACL, completely bypassing the DENY ACEs below. SYSTEM
//     can reassign ownership away from BA via SeTakeOwnershipPrivilege
//     (which it holds by default) regardless of the current DACL.
//
//  2. SYSTEM's own ALLOW ACE is listed FIRST, before the AU/BA DENY ACEs,
//     and explicitly includes WD (WRITE_DAC), SD (DELETE), DC
//     (CHANGE_CONFIG), and WO (WRITE_OWNER). The Go service manager opens
//     with SERVICE_ALL_ACCESS even for a later STOP/QUERY, so omitting DC/WO
//     blocks the sanctioned SYSTEM update helper. LocalSystem's
//     token includes both BUILTIN\Administrators (BA) and Authenticated
//     Users (AU) — Windows AccessCheck walks a security descriptor's ACEs in
//     the order they appear (not "all denies first"), granting each
//     requested right the first time a matching ALLOW ACE is seen, so a
//     right already granted by this earlier SY ALLOW ACE is not later
//     revoked by the AU/BA DENY ACEs even though LocalSystem's token also
//     carries those SIDs. Without this ordering (or full access for SY),
//     the DENY ACEs also block LocalSystem itself from stopping, unlocking,
//     or deleting the service — stalling performSelfRemoval() and leaving
//     the reaper script's stop-wait loop spinning forever.
const lockedServiceSDDL = "O:SYG:SY" +
	"D:" +
	"(A;;CCLCSWRPWPDTLOCRRCWDSDDCWO;;;SY)" +
	"(D;;WPDTCC;;;AU)" +
	"(D;;WPDTCC;;;BA)" +
	"(A;;CCLCSWLOCRRC;;;IU)" +
	"(A;;CCLCSWLOCRRC;;;SU)"

const unlockedServiceSDDL = "O:SYG:SY" +
	"D:" +
	"(A;;CCLCSWRPWPDTLOCRRCWDSDDCWO;;;SY)" +
	"(A;;CCLCSWRPWPDTLOCRRC;;;BA)" +
	"(A;;CCLCSWLOCRRC;;;IU)" +
	"(A;;CCLCSWLOCRRC;;;SU)"

func sdSet(sddl string) error {
	out, err := exec.Command("sc", "sdset", serviceName, sddl).CombinedOutput()
	if err != nil {
		return fmt.Errorf("sc sdset: %w: %s", err, string(out))
	}
	return nil
}

func hardenService() error {
	return sdSet(lockedServiceSDDL)
}

func unlockService() error {
	return sdSet(unlockedServiceSDDL)
}

// hardenDataDir grants SYSTEM full control and everyone else read-only.
// Nothing outside the SYSTEM-run agent process itself needs to write here —
// config.json, credentials.bin, and the mTLS client key/cert are all
// written by the service process only; the remote-desktop helper (which
// does run as the interactive user, not SYSTEM) talks to the service over
// named pipes (remote_pipe.go), not files in this directory. A standard
// user able to write config.json could point the agent at an
// attacker-controlled server URL/Ed25519 pubkey/TLS pin, which the SYSTEM
// service would then blindly trust on its next heartbeat — full SYSTEM
// compromise from a standard account. Read access (RX/REA) is kept so
// non-privileged diagnostics/log viewing still works.
//
// Deliberately NO explicit /deny for Authenticated Users here (an earlier
// version had one) — LocalSystem's own token carries the Authenticated
// Users SID as a group membership (same root cause already fixed for the
// SERVICE's SDDL in lockedServiceSDDL below), and empirically icacls does
// not reliably preserve grant-before-deny command-line ordering the way a
// raw SDDL string does, so that deny ACE could end up evaluated before
// SYSTEM's own grant — denying the service's own writes into this folder
// (observed live: "config.json.tmp" and later "nonces.dat.tmp" both got
// Access Denied while the service was actively enrolling/running).
// /inheritance:r already strips every inherited ACE, so simply never
// granting Authenticated Users write access is sufficient — Windows
// defaults to implicit deny for anything not explicitly granted; no
// explicit deny is needed, and adding one only risks catching SYSTEM too.
func hardenDataDir() error {
	out, err := exec.Command("icacls", dataDir,
		"/inheritance:r",
		"/grant:r", "SYSTEM:(OI)(CI)(F)",
		"/grant:r", "Authenticated Users:(OI)(CI)(RX,REA)",
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("icacls hardening: %w: %s", err, string(out))
	}
	return nil
}

func unlockDataDir(path string) error {
	out, err := exec.Command("icacls", path,
		"/reset", "/T",
		"/grant:r", "SYSTEM:(OI)(CI)(F)",
		"/grant:r", "Administrators:(OI)(CI)(F)",
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("icacls unlock: %w: %s", err, string(out))
	}
	return nil
}

// createSystemOnlyDirectory creates a privileged execution/staging directory
// whose contents cannot be replaced by an interactive user between integrity
// verification and execution. Administrators deliberately receive read-only
// access; LocalSystem is the only principal granted write access.
func createSystemOnlyDirectory(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	out, err := exec.Command("icacls", path,
		"/inheritance:r",
		"/grant:r", "SYSTEM:(OI)(CI)(F)",
		"/grant:r", "Administrators:(OI)(CI)(RX,REA)",
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("icacls SYSTEM-only directory: %w: %s", err, string(out))
	}
	return nil
}

func grantDirectoryRead(path, account string) error {
	if account == "" || strings.ContainsAny(account, "\r\n\x00") {
		return fmt.Errorf("invalid account name")
	}
	out, err := exec.Command("icacls", path,
		"/grant:r", account+":(OI)(CI)(RX,REA)",
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("icacls read grant: %w: %s", err, string(out))
	}
	return nil
}

// applyTamperProtection is called once, right after installService() succeeds.
func applyTamperProtection() {
	if err := hardenService(); err != nil {
		logError("Failed to harden service ACL: %v", err)
	}
	if err := hardenDataDir(); err != nil {
		logError("Failed to harden data directory ACL: %v", err)
	}
}
