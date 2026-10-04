package main

import ("encoding/json";"errors";"strings";"sync";"time";"unicode";"golang.org/x/sys/windows")

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
