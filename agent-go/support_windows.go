package main

// This pipe accepts only a bounded help request. It cannot execute commands,
// return credentials, start remote control or grant privilege.
import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"
	"unsafe"
)

const supportPipeName = `\\.\pipe\WardenSupport.v1`

var supportMessageFromUI string

type supportRequest struct {
	Message string `json:"message"`
}
type supportResponse struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

func validateSupportMessage(message string) error {
	if strings.TrimSpace(message) == "" || len(message) > 2000 {
		return errors.New("enter a message of at most 2000 bytes")
	}
	for _, c := range message {
		if unicode.IsControl(c) && c != '\n' && c != '\t' {
			return errors.New("invalid control character in message")
		}
	}
	return nil
}
func namedPipeUser(h windows.Handle, server bool) (string, string, error) {
	procedure := "GetNamedPipeClientProcessId"
	if server {
		procedure = "GetNamedPipeServerProcessId"
	}
	var pid uint32
	ok, _, err := kernel32DLL.NewProc(procedure).Call(uintptr(h), uintptr(unsafe.Pointer(&pid)))
	if ok == 0 {
		return "", "", err
	}
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", "", err
	}
	defer windows.CloseHandle(process)
	var token windows.Token
	if err = windows.OpenProcessToken(process, windows.TOKEN_QUERY, &token); err != nil {
		return "", "", err
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return "", "", err
	}
	account, domain, _, err := user.User.Sid.LookupAccount("")
	if err != nil {
		return "", "", err
	}
	return domain + "\\" + account, user.User.Sid.String(), nil
}
func createSupportPipe() (windows.Handle, error) {
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;;GA;;;SY)(A;;GRGW;;;IU)")
	if err != nil {
		return 0, err
	}
	attributes := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: descriptor}
	name, _ := windows.UTF16PtrFromString(supportPipeName)
	return windows.CreateNamedPipe(name, windows.PIPE_ACCESS_DUPLEX|0x00080000, windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT|0x8, 1, 8192, 8192, 0, attributes)
}
func runSupportBroker(stop <-chan struct{}) {
	last := map[string]time.Time{}
	for !stopRequested(stop) {
		h, err := createSupportPipe()
		if err != nil {
			logWarn("Support pipe unavailable: %v", err)
			timer := time.NewTimer(time.Second)
			select {
			case <-stop:
				timer.Stop()
				return
			case <-timer.C:
			}
			continue
		}
		var closeOnce sync.Once
		closePipe := func() { closeOnce.Do(func() { windows.CloseHandle(h) }) }
		connected := make(chan error, 1)
		go func() { connected <- connectNamedPipeTolerant(h) }()
		select {
		case <-stop:
			closePipe()
			return
		case err = <-connected:
		}
		if err != nil {
			closePipe()
			continue
		}
		timeout := time.AfterFunc(20*time.Second, closePipe)
		username, sid, err := namedPipeUser(h, false)
		response := supportResponse{Message: "Support request could not be sent. Please try again."}
		if err == nil && sid != "S-1-5-18" {
			raw, readErr := readIdentityBrokerFrame(pipeFile{h})
			var request supportRequest
			if readErr == nil && json.Unmarshal(raw, &request) == nil && validateSupportMessage(request.Message) == nil {
				if time.Since(last[sid]) < time.Minute {
					response.Message = "A request was just submitted. Wait a minute before retrying."
				} else {
					last[sid] = time.Now()
					result, postErr := apiPost("/api/agent/support-request", map[string]interface{}{"username": username, "message": request.Message}, true, 10)
					if postErr == nil && result["ok"] == true {
						response = supportResponse{OK: true, Message: "Your support request is in the queue. Remote access still requires your approval."}
					}
				}
			}
		}
		encoded, _ := json.Marshal(response)
		_ = writeIdentityBrokerFrame(pipeFile{h}, encoded)
		timeout.Stop()
		closePipe()
		for sid, at := range last {
			if time.Since(at) > time.Hour {
				delete(last, sid)
			}
		}
	}
}
func runSupportCLI(message string) int {
	supportMessageFromUI = ""
	if message == "" {
		message = "Please describe the problem and click Send request."
	}
	if runWardenUserDialog("Warden Support", "Ask your IT team for help", message, "This sends your description and Windows account name to your organization's Warden console. It does not grant remote access.", "info", true) != 0 {
		return 2
	}
	message = supportMessageFromUI
	if err := validateSupportMessage(message); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	name, _ := windows.UTF16PtrFromString(supportPipeName)
	h, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		runWardenUserDialog("Warden Support unavailable", "Could not reach the Warden service", "Your request was not sent. Ask your IT team to check the agent.", "", "warning", false)
		return 1
	}
	var once sync.Once
	closePipe := func() { once.Do(func() { windows.CloseHandle(h) }) }
	defer closePipe()
	timeout := time.AfterFunc(25*time.Second, closePipe)
	defer timeout.Stop()
	_, sid, err := namedPipeUser(h, true)
	if err != nil || sid != "S-1-5-18" {
		return 1
	}
	encoded, _ := json.Marshal(supportRequest{Message: message})
	if err = writeIdentityBrokerFrame(pipeFile{h}, encoded); err != nil {
		return 1
	}
	raw, err := readIdentityBrokerFrame(pipeFile{h})
	if err != nil {
		return 1
	}
	var result supportResponse
	if json.Unmarshal(raw, &result) != nil {
		return 1
	}
	severity := "warning"
	if result.OK {
		severity = "info"
	}
	runWardenUserDialog("Warden Support", "Request status", result.Message, "No remote access has been granted.", severity, false)
	if !result.OK {
		return 1
	}
	return 0
}
func ensureSupportShortcut() {
	exe, err := os.Executable()
	if err != nil || !strings.EqualFold(filepath.Dir(exe), installDir) {
		return
	}
	shortcut := filepath.Join(os.Getenv("ProgramData"), "Microsoft", "Windows", "Start Menu", "Programs", "Warden Support.lnk")
	if _, err = os.Stat(shortcut); err == nil {
		return
	}
	quote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
	script := "$w=New-Object -ComObject WScript.Shell; $s=$w.CreateShortcut(" + quote(shortcut) + "); $s.TargetPath=" + quote(exe) + "; $s.Arguments='--request-support'; $s.Description='Request help from your IT team'; $s.Save()"
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err = cmd.Run(); err != nil {
		logWarn("Could not create Warden Support shortcut")
	}
}
