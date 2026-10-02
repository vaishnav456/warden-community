# Unattended Windows application removal (2.6.54 candidate)

The CPU-Z 2.18 failure on Akshay was a 300-second UNINSTALL_APP timeout with
empty output. The old code read only UninstallString and added quiet flags only
for bare msiexec. Its current reported inventory still listed CPU-Z; no live
registry or process inspection has yet proven which confirmation was waiting.

## Changes

- Prefer the selected registration's QuietUninstallString.
- Identify Inno Setup by both its _is1 registry key and uninsNNN.exe filename.
  Use /VERYSILENT /SUPPRESSMSGBOXES /NORESTART. Do not guess these switches from
  an application name alone or add /S to arbitrary executables.
- Handle MSI /I maintenance strings as /x removal for the registered product GUID.
  Always request quiet execution and suppress reboot. Pin msiexec to the trusted
  Windows System32/SysWOW64 binary rather than searching PATH.
- Expand Windows %VARIABLE% command paths, preserve quoted command-line parsing
  and retain the existing protected executable roots and process-tree containment.
- Reject ambiguous duplicate display names and unsupported interactive uninstallers
  before launching. No automatic retry or user-process termination is introduced.
- Verify the selected registry key disappeared after an otherwise successful exit.
  A successful process exit with the registration still present is not reported
  as confirmed removal. A short five-second verification grace period allows
  asynchronous registration cleanup.
- MSI 3010 is explicitly reported as restart required, without initiating a reboot.
  If the registration remains, the job log says removal is pending restart rather
  than claiming the app was removed. Other nonzero exits and timeouts remain failures.

Vendor-registered quiet commands retain their own documented behavior; Warden
does not invent vendor-specific restart controls. Unsupported MSI file targets,
additional transforms/actions or nonstandard properties are rejected rather than
rewritten into potentially different operations. Registered product-code MSI
uninstall strings are supported. The five-minute execution deadline is unchanged.

HKCU from the SYSTEM service is SYSTEM's hive, not an arbitrary signed-in user's
profile. This change does not add per-user impersonation or AppX removal.
Registry disappearance verifies the selected uninstall registration, not that
every shared file, driver or user preference was deleted. Software inventory is
a reported snapshot and may require a later refresh.

## Tests and rollout boundary

Portable tests: from agent-go, run
`go test app_uninstall_rules.go app_uninstall_rules_test.go`.
Windows planner and existing native agent tests require Windows; use
`go test -vet=off ./...` on the designated development laptop. Existing vet
warnings in unrelated unsafe.Pointer interop are not fixed or suppressed as
evidence of a clean static analysis pass.

Full Windows-agent compilation is possible with GOOS=windows GOARCH=amd64.
Cross-compilation is not proof that the native tests executed. This candidate
must pass a native Windows pilot before signing/publishing an agent update and
retrying the CPU-Z removal on Akshay. No fleet rollout is implied.

References:
- [Inno Setup uninstaller parameters](https://jrsoftware.org/ishelp/topic_uninstcmdline.htm)
- [Microsoft Installer options](https://learn.microsoft.com/en-us/windows/win32/msi/standard-installer-command-line-options)
