package main

// uninstall.go — sanctioned local removal path for `warden-agent.exe uninstall`.
//
// This command does not remove anything on its
// own authority. It fetches pending jobs from the server (the same
// heartbeat endpoint the running service uses) and only acts if it finds a
// job whose operation is UNINSTALL_AGENT and which passes the exact same
// Ed25519 signature + nonce verification as any other job — reusing
// processJob(), which already routes a verified UNINSTALL_AGENT job to
// performSelfRemoval(). That job only exists once an admin has dispatched
// it from the Warden console (dual-approval gated).
//
// Must be run elevated (as SYSTEM or an account with
// SeTakeOwnershipPrivilege) so it can reverse the ACL/SDDL lockdown from
// tamper.go before removing files.

import (
	"encoding/json"
	"fmt"
)

func runUninstallCLI() int {
	if err := loadConfig(); err != nil {
		fmt.Println("Agent is not enrolled on this machine — nothing to uninstall.")
		return 1
	}
	c := getConfig()

	key, err := loadAPIKey()
	if err != nil {
		fmt.Printf("Could not load agent credentials: %v\n", err)
		return 1
	}
	if err := initComms(key, effectiveCertFingerprints(c)); err != nil {
		fmt.Printf("Could not initialize pinned communications: %v\n", err)
		return 1
	}
	pubKey, err := loadServerPubkey(c.ServerEd25519Pubkey)
	if err != nil {
		fmt.Printf("Invalid server public key: %v\n", err)
		return 1
	}
	if err := initReplayStore(); err != nil {
		fmt.Printf("Could not initialize durable replay protection: %v\n", err)
		return 1
	}

	jobs, err := postHeartbeat(1)
	if err != nil {
		fmt.Printf("Could not reach the Warden server: %v\n", err)
		return 1
	}

	for _, rawJob := range jobs {
		var peek struct {
			Operation string `json:"operation"`
		}
		if err := json.Unmarshal(rawJob, &peek); err != nil || peek.Operation != "UNINSTALL_AGENT" {
			continue // leave any other pending job for the running service to handle
		}
		fmt.Println("Found a pending UNINSTALL_AGENT job — verifying signature...")
		processJob(rawJob, pubKey) // verifies signature+nonce, dispatches, reports result
		fmt.Println("Uninstall job processed. Check agent.log for the outcome.")
		return 0
	}

	fmt.Println(
		"No approved uninstall job is pending for this endpoint.\n" +
			"An admin must dispatch 'UNINSTALL_AGENT' from the Warden console " +
			"(and it must clear dual-approval) before this command will do anything.",
	)
	return 1
}
