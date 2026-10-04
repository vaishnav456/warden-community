package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/windows/svc"
)

func main() {
	// If a command-line argument is given, handle service management
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "--ui-preview":
			// Harmless visual preview: no approval, network request or job.
			os.Exit(runWardenUserDialog("Warden design preview", "A calmer workspace. The same control.",
				"WINDOWS UI PREVIEW ONLY\n\nTry the mouse wheel, scrollbar thumb and keyboard navigation.\n\n"+
					strings.Repeat("Sample detail: this is design-preview text, not a real endpoint event.\n", 18)+
					"\nEND OF PREVIEW. No access, support request or device setting has been changed.",
				"Preview only. Real approvals still require an explicit choice; closing them denies access.", "info", false))
			return
		case "--support-status":
			os.Exit(runSupportStatusCLI())
			return
		case "--workspace":
			os.Exit(runFloatingWorkspace())
			return
		case "--request-support":
			message := ""
			if len(os.Args) > 2 {
				message = strings.Join(os.Args[2:], " ")
			}
			os.Exit(runSupportCLI(message))
			return
		case "--home-deletion-confirm":
			if len(os.Args) != 3 {
				os.Exit(2)
			}
			os.Exit(runWardenUserDialog("Warden Home deletions", "Confirm intentionally deleted files", os.Args[2], "Closing this screen postpones deletion. Nothing is restored until you choose.", "warning", true))
			return
		case "--reinstall-helper":
			if len(os.Args) != 8 {
				os.Exit(2)
			}
			requireSignature, err := strconv.ParseBool(os.Args[5])
			if err != nil {
				os.Exit(2)
			}
			os.Exit(runReinstallHelper(os.Args[2], os.Args[3], os.Args[4], requireSignature, os.Args[6], os.Args[7]))
			return
		case "--remote-consent":
			if len(os.Args) < 6 || len(os.Args) > 7 {
				os.Exit(2)
			}
			var requestedAccess []string
			if len(os.Args) == 7 {
				_ = json.Unmarshal([]byte(os.Args[6]), &requestedAccess)
			}
			os.Exit(runRemoteConsentPrompt(os.Args[2], os.Args[3], os.Args[4], os.Args[5], requestedAccess))
			return
		case "--user-announcement":
			if len(os.Args) != 5 {
				os.Exit(2)
			}
			os.Exit(runWardenUserDialog(os.Args[2], os.Args[2], os.Args[3], "Sent securely by your organization through Warden.", os.Args[4], false))
			return
		case "--user-notification":
			if len(os.Args) != 5 {
				os.Exit(2)
			}
			os.Exit(runWardenWindow(os.Args[2], os.Args[2], os.Args[3], "Warden notification", os.Args[4], false, true))
			return
		case "--apply-user-wallpaper":
			if len(os.Args) != 4 {
				os.Exit(2)
			}
			if err := applyInteractiveWallpaper(os.Args[2], os.Args[3]); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			return
		case "--remote-helper":
			if len(os.Args) != 4 {
				fmt.Fprintln(os.Stderr, "usage: warden-agent.exe --remote-helper <out_pipe_name> <in_pipe_name>")
				os.Exit(1)
			}
			// Best-effort only: this process usually runs as the interactive
			// user, and dataDir is ACL'd SYSTEM-only (hardenDataDir(), in
			// tamper.go), so this typically fails silently and falls back to
			// a discarded stderr — expected and fine. It only actually
			// succeeds when this helper is running as SYSTEM (the Winlogon
			// case), which covers the one gap the pipe-based 'L' log
			// forwarding in remote_helper.go can't: failures before the pipe
			// handshake itself has completed.
			initLogging()
			os.Exit(runRemoteHelper(os.Args[2], os.Args[3]))
			return
		case "install":
			// A freshly generated installer is also the supported reconnect
			// path for an endpoint that was removed from Warden while its local
			// service remained installed. Reuse and re-enrol that service in
			// place instead of attempting to create a duplicate service.
			existing, err := serviceInstalled()
			if err != nil {
				fmt.Fprintf(os.Stderr, "install failed: inspect existing service: %v\n", err)
				os.Exit(1)
			}
			if existing {
				// Repair the build-pinned provider before restarting the service.
				// Starting first makes the startup integrity check fail on a fresh
				// machine and leaves the protected service stopped until reboot.
				if err := installCredentialProviderFromInstaller(); err != nil {
					fmt.Fprintf(os.Stderr, "Credential Provider install failed: %v\n", err)
					os.Exit(1)
				}
				if err := reconnectExistingService(); err != nil {
					fmt.Fprintf(os.Stderr, "reconnect failed: %v\n", err)
					os.Exit(1)
				}
				waitForEnrollmentOrTimeout(30 * time.Second)
				applyTamperProtection()
				if !isEnrolled() {
					fmt.Fprintln(os.Stderr, "reconnect failed: enrollment did not complete; check agent.log")
					os.Exit(1)
				}
				fmt.Println("Existing Warden Agent re-enrolled and restarted.")
				return
			}
			// Copies this exe into dataDir and seeds dataDir's config.json
			// from whatever's staged alongside the currently-running exe
			// (the MSI's Program Files staging component, an extracted
			// zip, etc.) — see selfRelocateAndSeedConfig()'s doc comment.
			// Must run before installService(), which registers the
			// service against installedExePath, not wherever this process
			// happens to be running from right now.
			if err := selfRelocateAndSeedConfig(); err != nil {
				fmt.Fprintf(os.Stderr, "install failed: %v\n", err)
				os.Exit(1)
			}
			if err := installCredentialProviderFromInstaller(); err != nil {
				fmt.Fprintf(os.Stderr, "Credential Provider install failed: %v\n", err)
				os.Exit(1)
			}
			if err := installService(); err != nil {
				fmt.Fprintf(os.Stderr, "install failed: %v\n", err)
				os.Exit(1)
			}
			// dataDir must exist before hardenDataDir() can set its ACL —
			// on a fresh machine nothing has created it yet (the agent's
			// own run loop normally does this, but that hasn't started).
			ensureDirs()
			// Must start BEFORE applyTamperProtection() locks the service's
			// ACL down to SYSTEM-only start/stop rights — after that point
			// nothing short of a reboot (where the SCM itself starts it as
			// SYSTEM) can start it, since not even Administrators are
			// granted SERVICE_START in the locked-down ACL (see tamper.go).
			// Starting first, then locking, means the lockdown never blocks
			// this one legitimate first start.
			if err := startService(); err != nil {
				fmt.Fprintf(os.Stderr, "start failed: %v\n", err)
				applyTamperProtection()
				os.Exit(1)
			}
			// Start() only waits for the SCM to report the service as
			// "Running" — svc.Execute() sends that status the moment it
			// spawns runAgent()'s goroutine, well before enrollment (the
			// network round-trip plus its own config.json/credentials.bin
			// writes into dataDir) has actually finished. Racing
			// hardenDataDir() (which resets that same folder's ACL) against
			// the service's first-ever write into it can deny that write
			// outright. Wait for enrollment to actually land on disk first;
			// fall back to a timeout so a genuinely failed enrollment
			// (bad token, no network) doesn't hang the install forever —
			// the lockdown still applies either way.
			waitForEnrollmentOrTimeout(30 * time.Second)
			applyTamperProtection()
			fmt.Println("Service installed and started.")
			return
		case "remove", "uninstall":
			// Not a direct removal: requires a signed, admin-approved
			// UNINSTALL_AGENT job fetched and verified from the server. See
			// uninstall.go / tamper.go for why this isn't removeService().
			os.Exit(runUninstallCLI())
			return
		case "start":
			if err := startService(); err != nil {
				fmt.Fprintf(os.Stderr, "start failed: %v\n", err)
				os.Exit(1)
			}
			fmt.Println("Service started.")
			return
		case "stop":
			if err := stopService(); err != nil {
				fmt.Fprintf(os.Stderr, "stop failed: %v\n", err)
				os.Exit(1)
			}
			fmt.Println("Service stopped.")
			return
		}
	}

	// Check if running as a Windows service
	isService, err := svc.IsWindowsService()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to determine if running as service: %v\n", err)
		os.Exit(1)
	}

	if isService {
		if err := svc.Run(serviceName, &wardenService{}); err != nil {
			logError("service run failed: %v", err)
			os.Exit(1)
		}
		return
	}

	// Standalone mode
	runAgent(nil)
}
