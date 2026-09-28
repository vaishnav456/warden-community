package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"golang.org/x/sys/windows"
)

const (
	identityBrokerPipeName = `\\.\pipe\WardenIdentityBroker.v1`
	identityBrokerMaxFrame = 8 * 1024
	identityBrokerTimeout  = 8
)

var identityUsernamePattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,20}$`)
var identityEmailPattern = regexp.MustCompile(`^[A-Za-z0-9.!#$%&'*+/=?^_{}|~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}$`)

type identityBrokerRequest struct {
	Version  int    `json:"version"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type identityBrokerResponse struct {
	OK            bool   `json:"ok"`
	Username      string `json:"username,omitempty"`
	LocalPassword string `json:"local_password,omitempty"`
	Message       string `json:"message,omitempty"`
}

type identityAuthenticator func(username, password string) (identityBrokerResponse, error)

func validateIdentityBrokerRequest(req identityBrokerRequest) error {
	if req.Version != 1 {
		return fmt.Errorf("unsupported protocol version")
	}
	if len(req.Username) > 254 || (!identityUsernamePattern.MatchString(req.Username) && !identityEmailPattern.MatchString(req.Username)) {
		return fmt.Errorf("enter a valid Warden email")
	}
	if req.Password == "" || len(req.Password) > 128 {
		return fmt.Errorf("enter a valid password")
	}
	return nil
}

func authenticateIdentityOnline(username, password string) (identityBrokerResponse, error) {
	result, err := apiPost(
		"/api/agent/identity/authenticate",
		map[string]interface{}{"username": username, "password": password},
		true,
		identityBrokerTimeout,
	)
	if err != nil {
		// Do not pass the HTTP response body through to LogonUI. It may contain
		// operational details and the error string is not a stable UI contract.
		if strings.Contains(err.Error(), "HTTP 401") {
			return identityBrokerResponse{Message: "The username or password is incorrect."}, nil
		}
		if strings.Contains(err.Error(), "HTTP 403") || strings.Contains(err.Error(), "HTTP 423") {
			return identityBrokerResponse{Message: "This Warden account cannot sign in on this device."}, nil
		}
		if strings.Contains(err.Error(), "HTTP 429") {
			return identityBrokerResponse{Message: "Too many attempts. Try again shortly."}, nil
		}
		return identityBrokerResponse{}, err
	}
	if result == nil || result["ok"] != true {
		return identityBrokerResponse{Message: "Warden could not verify this account."}, nil
	}
	canonical, _ := result["username"].(string)
	if canonical == "" {
		canonical = username
	}
	localPassword, ok, err := managedIdentityPassword(canonical)
	if err != nil {
		return identityBrokerResponse{}, fmt.Errorf("load device credential: %w", err)
	}
	if !ok {
		return identityBrokerResponse{Message: "This account is not provisioned on this computer."}, nil
	}
	// Home grants stay inside the LocalSystem agent process and are never sent
	// through the LogonUI pipe. Sync starts asynchronously after authentication.
	if rawHome, exists := result["home"]; exists {
		go syncWardenHome(canonical, rawHome)
	}
	return identityBrokerResponse{
		OK: true, Username: canonical, LocalPassword: localPassword,
	}, nil
}

func handleIdentityBrokerRequest(raw []byte, authenticate identityAuthenticator) identityBrokerResponse {
	var req identityBrokerRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return identityBrokerResponse{Message: "Invalid sign-in request."}
	}
	if err := validateIdentityBrokerRequest(req); err != nil {
		return identityBrokerResponse{Message: err.Error()}
	}
	response, err := authenticate(req.Username, req.Password)
	// Drop references to plaintext credentials as soon as the synchronous
	// authentication call returns. Go strings cannot be reliably zeroed, so
	// the broker never persists, logs, caches, or sends them anywhere else.
	req.Password = ""
	if err != nil {
		logWarn("Warden identity authentication unavailable: %v", err)
		return identityBrokerResponse{Message: "Warden sign-in is temporarily unavailable. Use another sign-in option."}
	}
	if response.OK && (!identityUsernamePattern.MatchString(response.Username) || response.LocalPassword == "") {
		return identityBrokerResponse{Message: "Warden returned an invalid account."}
	}
	return response
}

func writeIdentityBrokerFrame(w io.Writer, payload []byte) error {
	if len(payload) > identityBrokerMaxFrame {
		return fmt.Errorf("identity broker response too large")
	}
	header := make([]byte, 4)
	binary.LittleEndian.PutUint32(header, uint32(len(payload)))
	if _, err := w.Write(header); err != nil {
		return err
	}
	if len(payload) > 0 {
		_, err := w.Write(payload)
		return err
	}
	return nil
}

func readIdentityBrokerFrame(r io.Reader) ([]byte, error) {
	header, err := readExact(r, 4)
	if err != nil {
		return nil, err
	}
	length := binary.LittleEndian.Uint32(header)
	if length == 0 || length > identityBrokerMaxFrame {
		return nil, fmt.Errorf("invalid identity broker frame length %d", length)
	}
	return readExact(r, int(length))
}

func serveIdentityBrokerConnection(h windows.Handle) {
	defer windows.CloseHandle(h)
	defer windows.DisconnectNamedPipe(h)
	conn := pipeFile{h: h}
	raw, err := readIdentityBrokerFrame(conn)
	if err != nil {
		return
	}
	response := handleIdentityBrokerRequest(raw, authenticateIdentityOnline)
	encoded, err := json.Marshal(response)
	if err != nil {
		return
	}
	_ = writeIdentityBrokerFrame(conn, encoded)
}

func stopRequested(stopCh <-chan struct{}) bool {
	if stopCh == nil {
		return false
	}
	select {
	case <-stopCh:
		return true
	default:
		return false
	}
}

func runIdentityBroker(stopCh <-chan struct{}) {
	// Only LocalSystem may connect. The provider is loaded by LogonUI as
	// LocalSystem; administrators and ordinary interactive processes are
	// deliberately excluded so this cannot become a general password oracle.
	const systemOnlySDDL = "D:P(A;;GA;;;SY)"
	logInfo("Warden identity broker listening on %s", identityBrokerPipeName)
	for !stopRequested(stopCh) {
		h, err := createPipeServer(
			identityBrokerPipeName,
			windows.PIPE_ACCESS_DUPLEX,
			systemOnlySDDL,
		)
		if err != nil {
			logWarn("Could not create identity broker pipe: %v", err)
			time.Sleep(time.Second)
			continue
		}

		connected := make(chan error, 1)
		go func() { connected <- connectNamedPipeTolerant(h) }()
		select {
		case err = <-connected:
			if err != nil {
				windows.CloseHandle(h)
				if !stopRequested(stopCh) {
					logWarn("Identity broker pipe connection failed: %v", err)
				}
				continue
			}
			serveIdentityBrokerConnection(h)
		case <-stopCh:
			windows.CloseHandle(h)
			return
		}
	}
}
