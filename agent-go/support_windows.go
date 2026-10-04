package main

// This pipe accepts only a bounded help request. It cannot execute commands,
// return credentials, start remote control or grant privilege.
import (
	"context"
	"encoding/json"
	"errors"
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
	Action    string            `json:"action,omitempty"`
	Message   string            `json:"message"`
	RequestID string            `json:"request_id,omitempty"`
	MessageID string            `json:"message_id,omitempty"`
	Subject   string            `json:"subject,omitempty"`
	Category  string            `json:"category,omitempty"`
	Priority  string            `json:"priority,omitempty"`
	Fields    map[string]string `json:"fields,omitempty"`
	Page      int               `json:"page,omitempty"`
}
type supportResponse struct {
	OK        bool               `json:"ok"`
	Message   string             `json:"message"`
	Activity  *workspaceActivity `json:"activity,omitempty"`
	Data      *helpdeskData      `json:"data,omitempty"`
	RequestID string             `json:"request_id,omitempty"`
	ModulePath string            `json:"module_path,omitempty"`
	ModuleSHA256 string          `json:"module_sha256,omitempty"`
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
	descriptor, err := windows.SecurityDescriptorFromString("O:SYD:P(A;;GA;;;SY)(A;;GRGW;;;IU)")
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
			raw, readErr := readSupportFrame(pipeFile{h})
			var request supportRequest
			if readErr == nil && json.Unmarshal(raw, &request) == nil && supportActionValid(request) {
				if request.Action == "activity" {
					state := currentWorkspaceActivity()
					response = supportResponse{OK: true, Message: "Local activity status", Activity: &state}
				} else if request.Action == "module-launch" {
					response = helpdeskModuleLaunchResponse()
				} else if !supportReadOnly(request.Action) && time.Since(last[sid]) < 3*time.Second {
					response.Message = "A request was just submitted. Wait a minute before retrying."
				} else {
					if !supportReadOnly(request.Action) {
						last[sid] = time.Now()
					}
					response = supportServerRequest(request, username)
				}
			}
		}
		// Keep JSON within the broker's 8 KiB frame even with Unicode and
		// escaped punctuation. The complete conversation remains on the server.
		runes := []rune(response.Message)
		if len(runes) > 1000 {
			response.Message = string(runes[:1000]) + "\n[More replies available from IT]"
		}
		encoded, _ := json.Marshal(response)
		if len(encoded) > supportMaxFrame {
			encoded, _ = json.Marshal(supportResponse{Message: "Ticket data exceeded the safe response size. Contact IT support."})
		}
		_ = writeSupportFrame(pipeFile{h}, encoded)
		timeout.Stop()
		closePipe()
		for sid, at := range last {
			if time.Since(at) > time.Hour {
				delete(last, sid)
			}
		}
	}
}
func runSupportCLI(message string) int { return runHelpdeskCreate(message) }
func runSupportStatusCLI() int         { return runHelpdeskTickets() }

func exchangeSupportRequest(request supportRequest) (supportResponse, error) {
	name, _ := windows.UTF16PtrFromString(supportPipeName)
	// Identification-only SQOS: even a privileged pipe server must not
	// impersonate the signed-in user through this helpdesk connection.
	const identificationOnly = 0x00100000 | 0x00010000
	h, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, identificationOnly, 0)
	deadline := time.Now().Add(15 * time.Second)
	for supportConnectionRetryable(err) && time.Now().Before(deadline) {
		// Retry connection only; never resend a ticket mutation.
		time.Sleep(50 * time.Millisecond)
		h, err = windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, identificationOnly, 0)
	}
	if err != nil {
		return supportResponse{}, err
	}
	var once sync.Once
	closePipe := func() { once.Do(func() { windows.CloseHandle(h) }) }
	defer closePipe()
	timeout := time.AfterFunc(25*time.Second, closePipe)
	defer timeout.Stop()
	// Normal users cannot query a SYSTEM process token. Check ownership on
	// this connected pipe handle instead: normal users cannot assign SYSTEM.
	descriptor, err := windows.GetSecurityInfo(h, windows.SE_KERNEL_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil || !supportServerOwnerTrusted(descriptor) {
		return supportResponse{}, errors.New("untrusted support service")
	}
	encoded, _ := json.Marshal(request)
	if err = writeSupportFrame(pipeFile{h}, encoded); err != nil {
		return supportResponse{}, err
	}
	raw, err := readSupportFrame(pipeFile{h})
	if err != nil {
		return supportResponse{}, err
	}
	var result supportResponse
	if json.Unmarshal(raw, &result) != nil {
		return supportResponse{}, errors.New("invalid support response")
	}
	return result, nil
}

func supportConnectionRetryable(err error) bool {
	return errors.Is(err, windows.ERROR_PIPE_BUSY) || errors.Is(err, windows.ERROR_FILE_NOT_FOUND)
}

func supportServerOwnerTrusted(descriptor *windows.SECURITY_DESCRIPTOR) bool {
	if descriptor == nil {
		return false
	}
	owner, _, err := descriptor.Owner()
	return err == nil && owner != nil && owner.String() == "S-1-5-18"
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
