package main

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	wtsapi32                   = windows.NewLazySystemDLL("wtsapi32.dll")
	kernel32                   = windows.NewLazySystemDLL("kernel32.dll")
	procWTSQueryUserToken      = wtsapi32.NewProc("WTSQueryUserToken")
	procWTSQuerySessionInfo    = wtsapi32.NewProc("WTSQuerySessionInformationW")
	procWTSFreeMemory          = wtsapi32.NewProc("WTSFreeMemory")
	procActiveConsoleSessionID = kernel32.NewProc("WTSGetActiveConsoleSessionId")
)

const (
	wtsCurrentServer = 0
	wtsUserName      = 5
)

func activeConsoleSessionID() (uint32, error) {
	session, _, _ := procActiveConsoleSessionID.Call()
	if uint32(session) == 0xffffffff {
		return 0, fmt.Errorf("no active console session")
	}
	return uint32(session), nil
}

func sessionUsername(sessionID uint32) (string, error) {
	var buffer *uint16
	var bytesReturned uint32
	ok, _, callErr := procWTSQuerySessionInfo.Call(
		wtsCurrentServer,
		uintptr(sessionID),
		wtsUserName,
		uintptr(unsafe.Pointer(&buffer)),
		uintptr(unsafe.Pointer(&bytesReturned)),
	)
	if ok == 0 {
		return "", fmt.Errorf("WTSQuerySessionInformationW: %w", callErr)
	}
	defer procWTSFreeMemory.Call(uintptr(unsafe.Pointer(buffer)))
	return windows.UTF16PtrToString(buffer), nil
}

func activeUserPrimaryToken(username string) (windows.Token, error) {
	sessionID, err := activeConsoleSessionID()
	if err != nil {
		return 0, err
	}
	actual, err := sessionUsername(sessionID)
	if err != nil {
		return 0, err
	}
	if !strings.EqualFold(actual, username) {
		return 0, fmt.Errorf(
			"requested run_as user %q is not active console user %q",
			username, actual,
		)
	}
	var impersonation windows.Token
	ok, _, callErr := procWTSQueryUserToken.Call(
		uintptr(sessionID), uintptr(unsafe.Pointer(&impersonation)),
	)
	if ok == 0 {
		return 0, fmt.Errorf("WTSQueryUserToken: %w", callErr)
	}
	defer impersonation.Close()

	var primary windows.Token
	err = windows.DuplicateTokenEx(
		impersonation,
		windows.MAXIMUM_ALLOWED,
		nil,
		windows.SecurityImpersonation,
		windows.TokenPrimary,
		&primary,
	)
	if err != nil {
		return 0, fmt.Errorf("DuplicateTokenEx: %w", err)
	}
	return primary, nil
}

// activeConsoleUserStringSID resolves the string SID of whichever user
// currently owns the interactive console session. Used to scope the
// remote-desktop helper's named pipes to exactly that user, instead of a
// broad group like Authenticated Users (which also covers any remote or
// network-authenticated account able to reach this machine's named-pipe
// namespace, not just the local interactive user).
func activeConsoleUserStringSID() (string, error) {
	sessionID, err := activeConsoleSessionID()
	if err != nil {
		return "", err
	}
	username, err := sessionUsername(sessionID)
	if err != nil {
		return "", fmt.Errorf("could not resolve user for session %d: %w", sessionID, err)
	}

	accountPtr, err := windows.UTF16PtrFromString(username)
	if err != nil {
		return "", err
	}

	// Two-pass LookupAccountName: first call sizes the SID + domain name
	// buffers, second call fills them.
	var sidLen, domainLen uint32
	var use uint32
	_ = windows.LookupAccountName(nil, accountPtr, nil, &sidLen, nil, &domainLen, &use)
	if sidLen == 0 {
		return "", fmt.Errorf("LookupAccountName: could not size SID buffer for %q", username)
	}
	sidBuf := make([]byte, sidLen)
	domainBuf := make([]uint16, domainLen)
	err = windows.LookupAccountName(
		nil, accountPtr,
		(*windows.SID)(unsafe.Pointer(&sidBuf[0])), &sidLen,
		&domainBuf[0], &domainLen, &use,
	)
	if err != nil {
		return "", fmt.Errorf("LookupAccountName(%q): %w", username, err)
	}

	sid := (*windows.SID)(unsafe.Pointer(&sidBuf[0]))
	var strPtr *uint16
	if err := windows.ConvertSidToStringSid(sid, &strPtr); err != nil {
		return "", fmt.Errorf("ConvertSidToStringSid: %w", err)
	}
	return windows.UTF16PtrToString(strPtr), nil
}

// lookupWindowsAccountIdentity resolves a SAM account name to the stable SID
// and authority/domain Windows associates with it. The central directory uses
// the SID for identity matching; usernames alone are mutable and can collide.
func lookupWindowsAccountIdentity(username string) (string, string, error) {
	accountPtr, err := windows.UTF16PtrFromString(username)
	if err != nil {
		return "", "", err
	}
	var sidLen, domainLen, use uint32
	_ = windows.LookupAccountName(nil, accountPtr, nil, &sidLen, nil, &domainLen, &use)
	if sidLen == 0 {
		return "", "", fmt.Errorf("LookupAccountName: could not size SID for %q", username)
	}
	sidBuf := make([]byte, sidLen)
	domainBuf := make([]uint16, domainLen)
	var domainPtr *uint16
	if len(domainBuf) > 0 {
		domainPtr = &domainBuf[0]
	}
	err = windows.LookupAccountName(
		nil, accountPtr,
		(*windows.SID)(unsafe.Pointer(&sidBuf[0])), &sidLen,
		domainPtr, &domainLen, &use,
	)
	if err != nil {
		return "", "", fmt.Errorf("LookupAccountName(%q): %w", username, err)
	}
	sid := (*windows.SID)(unsafe.Pointer(&sidBuf[0]))
	return sid.String(), windows.UTF16ToString(domainBuf), nil
}

// interactiveHelper is a handle to a long-running process launched into the
// active console session via launchInteractiveHelper(). Caller must call
// terminate() exactly once when done.
type interactiveHelper struct {
	process windows.Handle
	thread  windows.Handle
	pid     uint32
	token   windows.Token
}

func createInteractiveProcess(primary windows.Token, desktopName, exePath string, args []string) (*interactiveHelper, error) {
	cmdLine, err := windows.UTF16PtrFromString(
		windows.ComposeCommandLine(append([]string{exePath}, args...)),
	)
	if err != nil {
		primary.Close()
		return nil, err
	}

	desktop, err := windows.UTF16PtrFromString(desktopName)
	if err != nil {
		primary.Close()
		return nil, err
	}

	si := windows.StartupInfo{
		Cb:         uint32(unsafe.Sizeof(windows.StartupInfo{})),
		Desktop:    desktop,
		Flags:      windows.STARTF_USESHOWWINDOW,
		ShowWindow: windows.SW_HIDE,
	}
	var pi windows.ProcessInformation

	err = windows.CreateProcessAsUser(
		primary, nil, cmdLine, nil, nil, false,
		windows.CREATE_NO_WINDOW|windows.CREATE_UNICODE_ENVIRONMENT,
		nil, nil, &si, &pi,
	)
	if err != nil {
		primary.Close()
		return nil, fmt.Errorf("CreateProcessAsUser(%s): %w", desktopName, err)
	}

	return &interactiveHelper{
		process: pi.Process, thread: pi.Thread, pid: pi.ProcessId, token: primary,
	}, nil
}

func userPrimaryTokenForSession(sessionID uint32) (windows.Token, error) {
	var impersonation windows.Token
	ok, _, callErr := procWTSQueryUserToken.Call(
		uintptr(sessionID), uintptr(unsafe.Pointer(&impersonation)),
	)
	if ok == 0 {
		return 0, fmt.Errorf("WTSQueryUserToken: %w", callErr)
	}
	defer impersonation.Close()

	var primary windows.Token
	if err := windows.DuplicateTokenEx(
		impersonation, windows.MAXIMUM_ALLOWED, nil,
		windows.SecurityImpersonation, windows.TokenPrimary, &primary,
	); err != nil {
		return 0, fmt.Errorf("DuplicateTokenEx: %w", err)
	}
	return primary, nil
}

// systemPrimaryTokenForSession duplicates the service's LocalSystem token and
// assigns the duplicate to the physical console session. This is the
// pre-login counterpart to WTSQueryUserToken: at Winlogon there is no user
// token by definition, but the SYSTEM service still needs a process in that
// session to capture/control the secure desktop.
func systemPrimaryTokenForSession(sessionID uint32) (windows.Token, error) {
	var processToken windows.Token
	access := uint32(
		windows.TOKEN_QUERY |
			windows.TOKEN_DUPLICATE |
			windows.TOKEN_ASSIGN_PRIMARY |
			windows.TOKEN_ADJUST_DEFAULT |
			windows.TOKEN_ADJUST_SESSIONID,
	)
	if err := windows.OpenProcessToken(windows.CurrentProcess(), access, &processToken); err != nil {
		return 0, fmt.Errorf("OpenProcessToken: %w", err)
	}
	defer processToken.Close()

	tokenUser, err := processToken.GetTokenUser()
	if err != nil {
		return 0, fmt.Errorf("GetTokenUser: %w", err)
	}
	if !tokenUser.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		return 0, fmt.Errorf("pre-login remote access requires the Warden service to run as LocalSystem")
	}

	var primary windows.Token
	if err := windows.DuplicateTokenEx(
		processToken, windows.MAXIMUM_ALLOWED, nil,
		windows.SecurityImpersonation, windows.TokenPrimary, &primary,
	); err != nil {
		return 0, fmt.Errorf("DuplicateTokenEx(LocalSystem): %w", err)
	}

	if err := windows.SetTokenInformation(
		primary,
		uint32(windows.TokenSessionId),
		(*byte)(unsafe.Pointer(&sessionID)),
		uint32(unsafe.Sizeof(sessionID)),
	); err != nil {
		primary.Close()
		return 0, fmt.Errorf("SetTokenInformation(TokenSessionId=%d): %w", sessionID, err)
	}
	return primary, nil
}

func (h *interactiveHelper) isAlive() bool {
	r, _ := windows.WaitForSingleObject(h.process, 0)
	return r != uint32(windows.WAIT_OBJECT_0)
}

func (h *interactiveHelper) terminate(timeout time.Duration) {
	if h.isAlive() {
		_ = windows.TerminateProcess(h.process, 0)
		windows.WaitForSingleObject(h.process, uint32(timeout/time.Millisecond))
	}
	windows.CloseHandle(h.thread)
	windows.CloseHandle(h.process)
	h.token.Close()
}

func (h *interactiveHelper) wait(timeout time.Duration) (uint32, bool) {
	result, _ := windows.WaitForSingleObject(h.process, uint32(timeout/time.Millisecond))
	if result != uint32(windows.WAIT_OBJECT_0) {
		return 0, false
	}
	var code uint32
	if err := windows.GetExitCodeProcess(h.process, &code); err != nil {
		return 0, false
	}
	windows.CloseHandle(h.thread)
	windows.CloseHandle(h.process)
	h.token.Close()
	return code, true
}

// launchInteractiveHelper launches a long-running process (not waited on)
// into whichever user session currently owns the active console — used for
// the remote-helper mode (see remote_helper.go), since SYSTEM's own session 0
// has no real desktop to capture/send input into. Caller must call
// terminate() on the returned handle.
func launchInteractiveHelper(exePath string, args []string) (*interactiveHelper, error) {
	sessionID, err := activeConsoleSessionID()
	if err != nil {
		return nil, fmt.Errorf("no interactive user session is currently active: %w", err)
	}

	primary, err := userPrimaryTokenForSession(sessionID)
	if err != nil {
		return nil, err
	}
	return createInteractiveProcess(primary, `winsta0\default`, exePath, args)
}

// launchRemoteDesktopHelper supports both sides of the Windows sign-in
// boundary. Prefer the normal user token/default desktop when one exists.
// ERROR_NO_TOKEN is expected at the login screen, so fall back to a
// LocalSystem token placed into the console session and launch on Winlogon.
// Other WTS errors still fail closed instead of silently elevating.
func launchRemoteDesktopHelper(exePath string, args []string) (*interactiveHelper, string, error) {
	sessionID, err := activeConsoleSessionID()
	if err != nil {
		return nil, "", fmt.Errorf("no console session is currently active: %w", err)
	}

	primary, userErr := userPrimaryTokenForSession(sessionID)
	if userErr == nil {
		helper, err := createInteractiveProcess(primary, `winsta0\default`, exePath, args)
		return helper, "default", err
	}

	if !errors.Is(userErr, syscall.Errno(1008)) { // ERROR_NO_TOKEN
		return nil, "", userErr
	}

	primary, err = systemPrimaryTokenForSession(sessionID)
	if err != nil {
		return nil, "", fmt.Errorf("pre-login token setup failed: %w", err)
	}
	helper, err := createInteractiveProcess(primary, `winsta0\Winlogon`, exePath, args)
	return helper, "winlogon", err
}

func launchRemoteDesktopHelperOn(exePath string, args []string, desktop string) (*interactiveHelper, string, error) {
	if desktop == "" {
		return launchRemoteDesktopHelper(exePath, args)
	}
	sessionID, err := activeConsoleSessionID()
	if err != nil {
		return nil, "", err
	}
	if desktop == "winlogon" {
		primary, err := systemPrimaryTokenForSession(sessionID)
		if err != nil {
			return nil, "", err
		}
		helper, err := createInteractiveProcess(primary, `winsta0\Winlogon`, exePath, args)
		return helper, "winlogon", err
	}
	primary, err := userPrimaryTokenForSession(sessionID)
	if err != nil {
		return nil, "", err
	}
	helper, err := createInteractiveProcess(primary, `winsta0\default`, exePath, args)
	return helper, "default", err
}

// ── Session lock/unlock tracking ────────────────────────────────────────────
//
// The service declares SERVICE_ACCEPT_SESSIONCHANGE (see service.go), so the
// SCM pushes a WTS_SESSION_LOCK/WTS_SESSION_UNLOCK notification straight to
// its control handler for the exact session in question — this replaces an
// earlier attempt (agent 2.1.9) that instead polled
// WTSQuerySessionInformation's WTSInfoEx/SessionFlags once a second. On a
// plain Windows 11 console session (not a Remote Desktop Session Host), that
// polled field read as "locked" essentially always, including immediately
// after the user had just signed in, permanently misdirecting the
// remote-desktop capture helper onto the Winlogon desktop even while the
// machine was genuinely unlocked and in active use. An event the OS itself
// pushes for a specific session is a materially different, stronger signal
// than a field that turned out to default to a misleading value here.

const (
	wtsSessionLock   = 0x7
	wtsSessionUnlock = 0x8
	wtsSessionLogon  = 0x5
	wtsSessionLogoff = 0x6
)

var (
	sessionLockMu    sync.RWMutex
	sessionLockKnown bool
	sessionLocked    bool
	sessionLockID    uint32
)

// recordSessionChange is called from service.go's control handler for every
// SERVICE_CONTROL_SESSIONCHANGE the SCM delivers.
func recordSessionChange(eventType uint32) {
	// x/sys/windows/svc forwards EventData as the raw pointer supplied to its
	// native service-control callback. Windows only guarantees that pointer is
	// valid for the duration of the callback, but Execute receives the request
	// later through a channel. Dereferencing it here can therefore read freed
	// memory. Warden controls the physical console, so query its current session
	// ID at the point we record the notification instead.
	sessionID, err := activeConsoleSessionID()
	if err != nil {
		return
	}
	applySessionChange(sessionID, eventType)
}

// applySessionChange keeps the console desktop state stable across the
// lock/logoff and logon/unlock event pairs Windows emits. In particular,
// logoff means the console is now owned by Winlogon; clearing the known state
// here made desiredRemoteDesktop fall back to WTSQueryUserToken while the old
// user token was being torn down. That transient answer could repeatedly move
// the capture helper between Default and Winlogon, which appeared as flicker
// in the remote viewer even though the physical display was stable.
func applySessionChange(sessionID, eventType uint32) {
	sessionLockMu.Lock()
	defer sessionLockMu.Unlock()
	switch eventType {
	case wtsSessionLock:
		sessionLockID, sessionLocked, sessionLockKnown = sessionID, true, true
	case wtsSessionUnlock, wtsSessionLogon:
		sessionLockID, sessionLocked, sessionLockKnown = sessionID, false, true
	case wtsSessionLogoff:
		// A logged-off console is the Winlogon desktop. Keep this state even
		// when Windows reuses the same numeric session ID; the corresponding
		// LOGON/UNLOCK event above is what safely returns it to Default.
		sessionLockID, sessionLocked, sessionLockKnown = sessionID, true, true
	}
}

// knownSessionLockState reports whether sessionID is locked, but only if an
// actual SESSIONCHANGE notification has been observed for it. The caller
// falls back to a different signal when known is false — e.g. right after
// service startup, before any lock/unlock has occurred since boot.
func knownSessionLockState(sessionID uint32) (locked bool, known bool) {
	sessionLockMu.RLock()
	defer sessionLockMu.RUnlock()
	if !sessionLockKnown || sessionLockID != sessionID {
		return false, false
	}
	return sessionLocked, true
}

// desiredRemoteDesktop reports which desktop currently owns the physical
// console. The relay polls this so it can replace its capture helper without
// dropping the browser WebSocket when a user signs in, signs out, locks, or
// unlocks. Prefers the OS-pushed lock/unlock state (see above) when one is
// known for this exact session; otherwise falls back to whether a signed-in
// user's token exists at all (ERROR_NO_TOKEN means Winlogon, pre-sign-in).
func desiredRemoteDesktop() (string, error) {
	sessionID, err := activeConsoleSessionID()
	if err != nil {
		return "", err
	}
	if locked, known := knownSessionLockState(sessionID); known {
		if locked {
			return "winlogon", nil
		}
		return "default", nil
	}
	token, err := userPrimaryTokenForSession(sessionID)
	if err == nil {
		token.Close()
		return "default", nil
	}
	if errors.Is(err, syscall.Errno(1008)) {
		return "winlogon", nil
	}
	return "", err
}

func runCommandAsUser(
	username, executable string, args []string, timeout time.Duration,
) (int, string, error) {
	token, err := activeUserPrimaryToken(username)
	if err != nil {
		return 1, "", err
	}
	defer token.Close()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Token:         syscall.Token(token),
		HideWindow:    true,
		CreationFlags: windows.CREATE_NO_WINDOW,
	}
	out, runErr := boundedCombinedOutput(cmd)
	if ctx.Err() == context.DeadlineExceeded {
		if cmd.Process != nil {
			_ = exec.Command(
				"taskkill", "/PID", fmt.Sprint(cmd.Process.Pid), "/T", "/F",
			).Run()
		}
		return 1, string(out), fmt.Errorf("process timed out after %s", timeout)
	}
	if runErr != nil {
		exitCode := 1
		if exitErr, ok := runErr.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		}
		return exitCode, string(out), runErr
	}
	return 0, string(out), nil
}
