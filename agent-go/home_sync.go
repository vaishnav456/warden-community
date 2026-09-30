package main

// Warden Home endpoint client. It performs a bounded sync immediately after a
// successful Warden identity login. File data goes directly to tenant-owned
// Home Nodes; grants are short-lived and never leave this LocalSystem process.

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type homeNode struct {
	ID             string   `json:"id"`
	LocalURL       string   `json:"local_url"`
	PublicURL      string   `json:"public_url"`
	TLSFingerprint string   `json:"tls_fingerprint"`
	CACertificate  string   `json:"ca_certificate_pem"`
	RequireMTLS    bool     `json:"require_mtls"`
	Writable       bool     `json:"writable"`
	Grant          string   `json:"grant"`
	ConnectionMode string   `json:"connection_mode"`
	P2PURL         string   `json:"p2p_url"`
	STUNURLs       []string `json:"stun_urls"`
}

type homeMapping struct {
	Source string `json:"source"`
	Target string `json:"target"`
}
type homeSpace struct {
	ID             string        `json:"id"`
	Name           string        `json:"name"`
	Type           string        `json:"type"`
	AccessMode     string        `json:"access_mode"`
	Prefix         string        `json:"prefix"`
	Mappings       []homeMapping `json:"mappings"`
	SyncMode       string        `json:"sync_mode"`
	ConflictPolicy string        `json:"conflict_policy"`
	MaxFileBytes   int64         `json:"max_file_bytes"`
	Nodes          []homeNode    `json:"nodes"`
}
type homeRemoteFile struct {
	Path          string `json:"path"`
	Size, ModTime int64
}

var allowedHomeFolders = map[string]bool{"Desktop": true, "Documents": true, "Downloads": true, "Pictures": true, "Music": true, "Videos": true}

func homeHTTPClient(node homeNode, username string) (*http.Client, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if strings.TrimSpace(node.CACertificate) != "" {
		roots, err := x509.SystemCertPool()
		if err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM([]byte(node.CACertificate)) {
			return nil, errors.New("home node private CA is invalid")
		}
		tlsCfg.RootCAs = roots
	}
	if cert, ok, err := loadClientCertificate(); err != nil {
		return nil, err
	} else if ok {
		tlsCfg.Certificates = []tls.Certificate{cert}
	} else if node.RequireMTLS {
		return nil, errors.New("home node requires mTLS but device certificate is unavailable")
	}
	// A leaf pin is optional because renewable public certificates receive a
	// new fingerprint on every ACME renewal. Normal CA-chain and hostname
	// verification always remains enabled. Operators may still pin a manually
	// managed, fixed certificate as an additional check.
	if strings.TrimSpace(node.TLSFingerprint) != "" {
		fp, err := normalizeFingerprint(node.TLSFingerprint)
		if err != nil {
			return nil, err
		}
		tlsCfg.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("home node supplied no certificate")
			}
			sum := sha256.Sum256(raw[0])
			if hex.EncodeToString(sum[:]) != fp {
				return errors.New("home node TLS fingerprint mismatch")
			}
			return nil
		}
	}
	transport := &http.Transport{TLSClientConfig: tlsCfg}
	if node.ConnectionMode == "p2p" {
		transport = newHomeP2PTLSTransport(tlsCfg, func() (net.Conn, error) {
			return dialHomeP2P(username, node)
		})
	}
	return &http.Client{Timeout: 10 * time.Minute, CheckRedirect: rejectRedirect, Transport: transport}, nil
}

func homeNodeURL(node homeNode) string {
	if node.ConnectionMode == "p2p" {
		return strings.TrimRight(node.P2PURL, "/")
	}
	if node.LocalURL != "" {
		return strings.TrimRight(node.LocalURL, "/")
	}
	return strings.TrimRight(node.PublicURL, "/")
}

func homeNodeCandidates(node homeNode) []homeNode {
	if node.ConnectionMode == "p2p" {
		return []homeNode{node}
	}
	var candidates []homeNode
	if strings.TrimSpace(node.LocalURL) != "" {
		local := node
		local.PublicURL = ""
		candidates = append(candidates, local)
	}
	if strings.TrimSpace(node.PublicURL) != "" && strings.TrimRight(node.PublicURL, "/") != strings.TrimRight(node.LocalURL, "/") {
		public := node
		public.LocalURL = ""
		candidates = append(candidates, public)
	}
	return candidates
}

func cleanHomePart(value string) (string, error) {
	value = strings.ReplaceAll(strings.TrimSpace(value), "\\", "/")
	value = strings.Trim(value, "/")
	clean := filepath.ToSlash(filepath.Clean(value))
	if clean == "" || clean == "." || strings.HasPrefix(clean, "../") || strings.Contains(clean, "/../") || filepath.IsAbs(clean) {
		return "", errors.New("invalid home path")
	}
	return clean, nil
}

func safeSharedFolderName(value string) string {
	value = strings.TrimSpace(value)
	var clean strings.Builder
	for _, r := range value {
		if r < 32 || strings.ContainsRune(`<>:"/\|?*`, r) {
			clean.WriteRune('-')
		} else {
			clean.WriteRune(r)
		}
	}
	result := strings.Trim(clean.String(), " .")
	if result == "" {
		result = "Shared files"
	}
	runes := []rune(result)
	if len(runes) > 80 {
		result = string(runes[:80])
	}
	upper := strings.ToUpper(result)
	reserved := upper == "CON" || upper == "PRN" || upper == "AUX" || upper == "NUL" ||
		(len(upper) == 4 && (strings.HasPrefix(upper, "COM") || strings.HasPrefix(upper, "LPT")) && upper[3] >= '1' && upper[3] <= '9')
	if reserved {
		result = "_" + result
	}
	return result
}

func localHomeRoot(username string, space homeSpace, source string) (string, error) {
	if !identityUsernamePattern.MatchString(username) {
		return "", errors.New("unsafe Warden Home mapping")
	}
	var root string
	if space.Type == "shared" {
		root = filepath.Join(`C:\Users`, username, "Warden Shares", safeSharedFolderName(space.Name))
	} else {
		if !allowedHomeFolders[source] {
			return "", errors.New("unsafe Warden Home mapping")
		}
		root = filepath.Join(`C:\Users`, username, source)
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	expected := strings.ToLower(filepath.Join(`C:\Users`, username) + string(os.PathSeparator))
	if !strings.HasPrefix(strings.ToLower(abs), expected) {
		return "", errors.New("profile path escaped")
	}
	return abs, nil
}

func homeRequest(client *http.Client, node homeNode, method, path string, body io.Reader, mtime int64) (*http.Response, error) {
	req, err := http.NewRequest(method, homeNodeURL(node)+"/v1/file?path="+url.QueryEscape(path), body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+node.Grant)
	if mtime > 0 {
		req.Header.Set("X-Warden-Mtime", time.Unix(mtime, 0).UTC().Format(time.RFC3339))
	}
	return client.Do(req)
}

func listHomeFiles(client *http.Client, node homeNode, prefix string) ([]homeRemoteFile, error) {
	req, _ := http.NewRequest(http.MethodGet, homeNodeURL(node)+"/v1/list?path="+url.QueryEscape(prefix), nil)
	req.Header.Set("Authorization", "Bearer "+node.Grant)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("home list HTTP %d", resp.StatusCode)
	}
	var files []homeRemoteFile
	err = json.NewDecoder(io.LimitReader(resp.Body, 8*1024*1024)).Decode(&files)
	return files, err
}

// Reports contain metadata only; grants and file contents never enter job logs.
type homeFileResult struct {
	Space  string `json:"space"`
	Path   string `json:"path"`
	Action string `json:"action"`
	Status string `json:"status"`
	Bytes  int64  `json:"bytes,omitempty"`
	Error  string `json:"error,omitempty"`
}

type homeSyncReport struct {
	Kind            string           `json:"kind"`
	Version         int              `json:"version"`
	Username        string           `json:"username"`
	StartedAt       string           `json:"started_at"`
	CompletedAt     string           `json:"completed_at"`
	Status          string           `json:"status"`
	Uploaded        int              `json:"uploaded"`
	Downloaded      int              `json:"downloaded"`
	Unchanged       int              `json:"unchanged"`
	Skipped         int              `json:"skipped"`
	Failed          int              `json:"failed"`
	UploadedBytes   int64            `json:"uploaded_bytes"`
	DownloadedBytes int64            `json:"downloaded_bytes"`
	Files           []homeFileResult `json:"files"`
	OmittedDetails  int              `json:"omitted_details"`
}

const homeReportDetailLimit = 100

func (report *homeSyncReport) record(space, path, action, status string, size int64, err error) {
	switch status {
	case "uploaded":
		report.Uploaded++
		report.UploadedBytes += size
	case "downloaded":
		report.Downloaded++
		report.DownloadedBytes += size
	case "unchanged":
		report.Unchanged++
	case "skipped":
		report.Skipped++
	case "failed":
		report.Failed++
	}
	detail := homeFileResult{Space: boundedHomeReportText(space, 256), Path: boundedHomeReportText(path, 1024), Action: action, Status: status, Bytes: size}
	if err != nil {
		detail.Error = boundedHomeReportText(err.Error(), 2048)
	}
	// Keep the error list useful even when many successful files precede it.
	if len(report.Files) < homeReportDetailLimit {
		report.Files = append(report.Files, detail)
	} else {
		report.OmittedDetails++
		if err != nil {
			for i := len(report.Files) - 1; i >= 0; i-- {
				if report.Files[i].Error == "" {
					report.Files[i] = detail
					break
				}
			}
		}
	}
}

func (report *homeSyncReport) merge(other homeSyncReport) {
	report.Uploaded += other.Uploaded
	report.Downloaded += other.Downloaded
	report.Unchanged += other.Unchanged
	report.Skipped += other.Skipped
	report.Failed += other.Failed
	report.UploadedBytes += other.UploadedBytes
	report.DownloadedBytes += other.DownloadedBytes
	report.OmittedDetails += other.OmittedDetails
	for _, detail := range other.Files {
		if len(report.Files) < homeReportDetailLimit {
			report.Files = append(report.Files, detail)
		} else {
			report.OmittedDetails++
			if detail.Error != "" {
				for i := len(report.Files) - 1; i >= 0; i-- {
					if report.Files[i].Error == "" {
						report.Files[i] = detail
						break
					}
				}
			}
		}
	}
}

func boundedHomeReportText(value string, limit int) string {
	runes := []rune(value)
	if len(runes) > limit {
		return string(runes[:limit]) + "…"
	}
	return value
}

func (report *homeSyncReport) transferError() error {
	if report.Failed == 0 && report.Skipped == 0 {
		return nil
	}
	for _, file := range report.Files {
		if file.Error != "" {
			return fmt.Errorf("%d failed, %d skipped; %s: %s", report.Failed, report.Skipped, file.Path, file.Error)
		}
	}
	return fmt.Errorf("%d failed, %d skipped", report.Failed, report.Skipped)
}

func syncHomeMapping(space homeSpace, node homeNode, m homeMapping, username string) (homeSyncReport, error) {
	var report homeSyncReport
	localRoot, err := localHomeRoot(username, space, m.Source)
	if err != nil {
		return report, err
	}
	if err := os.MkdirAll(localRoot, 0700); err != nil {
		return report, fmt.Errorf("create local Warden Home folder: %w", err)
	}
	client, err := homeHTTPClient(node, username)
	if err != nil {
		return report, err
	}
	defer client.CloseIdleConnections()
	return syncHomeMappingFiles(space, node, m, localRoot, client)
}

// This boundary also lets transfer failures be exercised against a real HTTP
// server and temporary folder without a signed-in Windows profile.
func syncHomeMappingFiles(space homeSpace, node homeNode, m homeMapping, localRoot string, client *http.Client) (homeSyncReport, error) {
	var report homeSyncReport
	target, err := cleanHomePart(m.Target)
	if err != nil {
		return report, err
	}
	remoteRoot := strings.Trim(space.Prefix, "/") + "/" + target
	remote, err := listHomeFiles(client, node, remoteRoot)
	if err != nil {
		return report, err
	}
	remoteByPath := map[string]homeRemoteFile{}
	for _, f := range remote {
		remoteByPath[f.Path] = f
	}
	handled := map[string]bool{}
	canUpload := space.AccessMode != "read" && space.SyncMode != "download"
	if space.SyncMode != "upload" {
		for _, f := range remote {
			if !strings.HasPrefix(f.Path, remoteRoot+"/") {
				report.record(space.Name, f.Path, "download", "failed", 0, errors.New("node returned a file outside the assigned folder"))
				continue
			}
			rel := strings.TrimPrefix(f.Path, remoteRoot+"/")
			clean, err := cleanHomePart(rel)
			if err != nil {
				report.record(space.Name, rel, "download", "failed", 0, err)
				continue
			}
			dst := filepath.Join(localRoot, filepath.FromSlash(clean))
			abs, _ := filepath.Abs(dst)
			if !strings.HasPrefix(strings.ToLower(abs), strings.ToLower(localRoot+string(os.PathSeparator))) {
				report.record(space.Name, rel, "download", "failed", 0, errors.New("download path escaped the local folder"))
				continue
			}
			info, statErr := os.Stat(abs)
			if statErr != nil && !os.IsNotExist(statErr) {
				report.record(space.Name, rel, "download", "failed", 0, statErr)
				continue
			}
			if f.Size < 0 || f.Size > space.MaxFileBytes {
				report.record(space.Name, rel, "download", "skipped", 0, errors.New("file exceeds the configured size limit"))
				continue
			}
			conflictPolicy := space.ConflictPolicy
			if space.AccessMode == "read" {
				conflictPolicy = "server_wins"
			}
			if statErr == nil && info.ModTime().Unix() == f.ModTime && info.Size() == f.Size {
				report.record(space.Name, rel, "compare", "unchanged", 0, nil)
				handled[f.Path] = true
				continue
			}
			if statErr == nil && conflictPolicy == "keep_both" && info.ModTime().Unix() != f.ModTime {
				if info.ModTime().Unix() > f.ModTime {
					abs = abs + ".server-conflict-" + time.Now().UTC().Format("20060102-150405")
				} else {
					if err := os.Rename(abs, abs+".local-conflict-"+time.Now().UTC().Format("20060102-150405")); err != nil {
						report.record(space.Name, rel, "download", "failed", 0, err)
						continue
					}
				}
			} else if statErr == nil && info.ModTime().Unix() > f.ModTime && conflictPolicy != "server_wins" {
				if !canUpload {
					report.record(space.Name, rel, "compare", "skipped", 0, errors.New("newer local file retained by conflict policy"))
				}
				continue
			}
			copied, err := downloadHomeFile(client, node, f, abs, space.MaxFileBytes)
			if err != nil {
				report.record(space.Name, rel, "download", "failed", 0, err)
				continue
			}
			report.record(space.Name, rel, "download", "downloaded", copied, nil)
			if abs == dst {
				handled[f.Path] = true
			}
		}
	}
	if !canUpload {
		return report, report.transferError()
	}
	if !node.Writable {
		return report, errors.New("selected replica is read-only; trying primary")
	}
	walkErr := filepath.Walk(localRoot, func(path string, info os.FileInfo, walkErr error) error {
		rel, err := filepath.Rel(localRoot, path)
		if err != nil {
			report.record(space.Name, m.Source, "scan", "failed", 0, err)
			return nil
		}
		if walkErr != nil {
			report.record(space.Name, rel, "scan", "failed", 0, walkErr)
			return nil
		}
		if info == nil || info.IsDir() {
			return nil
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			report.record(space.Name, rel, "upload", "skipped", 0, errors.New("only regular files can be synchronized"))
			return nil
		}
		if info.Size() > space.MaxFileBytes {
			report.record(space.Name, rel, "upload", "skipped", 0, errors.New("file exceeds the configured size limit"))
			return nil
		}
		remotePath := remoteRoot + "/" + filepath.ToSlash(rel)
		if handled[remotePath] {
			return nil
		}
		if rf, ok := remoteByPath[remotePath]; ok && (rf.ModTime > info.ModTime().Unix() || (rf.ModTime == info.ModTime().Unix() && rf.Size == info.Size())) {
			report.record(space.Name, rel, "compare", "unchanged", 0, nil)
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			report.record(space.Name, rel, "upload", "failed", 0, err)
			return nil
		}
		counter := &homeByteCounter{}
		resp, err := homeRequest(client, node, http.MethodPut, remotePath, io.TeeReader(f, counter), info.ModTime().Unix())
		f.Close()
		if err == nil {
			io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				err = fmt.Errorf("home upload HTTP %d", resp.StatusCode)
			}
			resp.Body.Close()
		}
		if err == nil && counter.n != info.Size() {
			err = errors.New("file changed during upload; retry the sync")
		}
		if err != nil {
			report.record(space.Name, rel, "upload", "failed", 0, err)
		} else {
			report.record(space.Name, rel, "upload", "uploaded", counter.n, nil)
		}
		return nil
	})
	if walkErr != nil {
		report.record(space.Name, m.Source, "scan", "failed", 0, walkErr)
	}
	return report, report.transferError()
}

type homeByteCounter struct{ n int64 }

func (counter *homeByteCounter) Write(p []byte) (int, error) {
	counter.n += int64(len(p))
	return len(p), nil
}

func downloadHomeFile(client *http.Client, node homeNode, file homeRemoteFile, dst string, maxBytes int64) (int64, error) {
	resp, err := homeRequest(client, node, http.MethodGet, file.Path, nil, 0)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("home download HTTP %d", resp.StatusCode)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0700); err != nil {
		return 0, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".warden-home-")
	if err != nil {
		return 0, err
	}
	defer os.Remove(tmp.Name())
	copied, err := io.Copy(tmp, io.LimitReader(resp.Body, maxBytes+1))
	closeErr := tmp.Close()
	if err != nil {
		return 0, err
	}
	if closeErr != nil {
		return 0, closeErr
	}
	if copied > maxBytes || copied != file.Size {
		return 0, fmt.Errorf("incomplete download: expected %d bytes, received %d", file.Size, copied)
	}
	// Failed replacements leave the existing local copy intact.
	if err := os.Rename(tmp.Name(), dst); err != nil {
		return 0, err
	}
	if err := os.Chtimes(dst, time.Now(), time.Unix(file.ModTime, 0)); err != nil {
		return 0, err
	}
	return copied, nil
}

func syncWardenHome(username string, raw interface{}) {
	time.Sleep(5 * time.Second)
	if err := syncWardenHomeNow(username, raw); err != nil {
		logWarn("Warden Home sync failed: %v", err)
	}
}

func syncWardenHomeNow(username string, raw interface{}) error {
	_, err := syncWardenHomeWithReport(username, raw)
	return err
}

func syncWardenHomeWithReport(username string, raw interface{}) (report homeSyncReport, finalErr error) {
	report = homeSyncReport{Kind: "warden_home_sync", Version: 1, Username: username, StartedAt: time.Now().UTC().Format(time.RFC3339), Files: []homeFileResult{}}
	defer func() {
		report.CompletedAt = time.Now().UTC().Format(time.RFC3339)
		report.Status = "completed"
		if finalErr != nil {
			report.Status = "failed"
		}
		notifyHomeSyncResult(report)
	}()
	encoded, err := json.Marshal(raw)
	if err != nil {
		return report, err
	}
	var spaces []homeSpace
	if err := json.Unmarshal(encoded, &spaces); err != nil {
		return report, err
	}
	if len(spaces) == 0 {
		return report, errors.New("no Warden Home spaces are assigned")
	}
	var failures []string
	hasSharedSpace := false
	for _, space := range spaces {
		if space.Type == "shared" {
			hasSharedSpace = true
		}
		if space.MaxFileBytes <= 0 {
			space.MaxFileBytes = 512 * 1024 * 1024
		}
		for _, mapping := range space.Mappings {
			last := errors.New("no home node address is configured")
			var mappingReport homeSyncReport
			for _, node := range space.Nodes {
				for _, candidate := range homeNodeCandidates(node) {
					var err error
					mappingReport, err = syncHomeMapping(space, candidate, mapping, username)
					if err == nil {
						last = nil
						break
					} else {
						last = err
					}
					if mappingReport.Failed+mappingReport.Skipped > 0 {
						break
					}
				}
				if last == nil || mappingReport.Failed+mappingReport.Skipped > 0 {
					break
				}
			}
			report.merge(mappingReport)
			if last != nil {
				if mappingReport.Failed+mappingReport.Skipped == 0 {
					report.record(space.Name, mapping.Target, "connect", "failed", 0, last)
				}
				logWarn("Warden Home sync for %s failed: %v", space.Name, last)
				failures = append(failures, space.Name+": "+last.Error())
			}
		}
		if len(space.Mappings) == 0 {
			report.record(space.Name, "", "configure", "failed", 0, errors.New("no folders are configured"))
			failures = append(failures, space.Name+": no folders are configured")
		}
	}
	if hasSharedSpace {
		if err := exposeWardenSharesDrive(username); err != nil {
			report.record("Warden Shares", "", "map_drive", "failed", 0, err)
			failures = append(failures, "Warden Shares drive: "+err.Error())
		}
	}
	if len(failures) > 0 {
		return report, errors.New(strings.Join(failures, "; "))
	}
	return report, nil
}

// Prefer W: for a recognizable Warden drive, then search every safe user
// drive letter. Limiting this to W: through R: made healthy shares fail on
// workstations that already had several mapped corporate drives.
var wardenDriveLetters = []string{
	"W:", "V:", "U:", "T:", "S:", "R:", "Q:", "P:", "O:", "N:",
	"M:", "L:", "K:", "J:", "I:", "H:", "G:", "F:", "E:", "D:",
}

// exposeWardenSharesDrive maps the local synchronized cache into the signed-in
// user's DOS-device namespace. A mapping created by LocalSystem in session 0
// would be invisible in Explorer, so every command runs with the user's token.
// The per-user Run value restores the same mapping after later sign-ins.
func exposeWardenSharesDrive(username string) error {
	if !identityUsernamePattern.MatchString(username) {
		return errors.New("invalid Warden Home username")
	}
	sessionID, err := activeConsoleSessionID()
	if err != nil {
		return errors.New("no interactive Windows session; sign in to map the drive")
	}
	activeUsername, err := sessionUsername(sessionID)
	if err != nil || !strings.EqualFold(activeUsername, username) {
		return fmt.Errorf("user %s is not signed in; the drive will map after sign-in", username)
	}
	root := filepath.Join(`C:\Users`, username, "Warden Shares")
	if err := os.MkdirAll(root, 0700); err != nil {
		return fmt.Errorf("create drive cache: %w", err)
	}
	marker := filepath.Join(root, ".warden-drive")
	if err := os.WriteFile(marker, []byte("Warden Home managed drive\n"), 0600); err != nil {
		return fmt.Errorf("create drive marker: %w", err)
	}
	_ = exec.Command("attrib.exe", "+H", marker).Run()

	for _, drive := range wardenDriveLetters {
		command := fmt.Sprintf(
			`if exist %s\.warden-drive exit /b 0 & if exist %s\ exit /b 17 & subst %s "%s"`,
			drive, drive, drive, root,
		)
		code, err := runInteractiveHomeCommand(username, "cmd.exe", []string{"/d", "/s", "/c", command})
		if err != nil || code == 17 || code != 0 {
			continue
		}
		letter := strings.TrimSuffix(drive, ":")
		runCommand := fmt.Sprintf(`cmd.exe /d /c subst %s "%s"`, drive, root)
		_, runErr := runInteractiveHomeCommand(username, "reg.exe", []string{
			"add", `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`,
			"/v", "WardenHomeDrive", "/t", "REG_SZ", "/d", runCommand, "/f",
		})
		_, labelErr := runInteractiveHomeCommand(username, "reg.exe", []string{
			"add", `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\DriveIcons\` + letter + `\DefaultLabel`,
			"/ve", "/t", "REG_SZ", "/d", "Warden Shares", "/f",
		})
		if runErr != nil || labelErr != nil {
			return errors.New("drive mapped but sign-in persistence could not be configured")
		}
		return nil
	}
	return fmt.Errorf("no free Warden Shares drive letter is available (checked W: through D:)")
}

func runInteractiveHomeCommand(username, executable string, args []string) (uint32, error) {
	token, err := activeUserPrimaryToken(username)
	if err != nil {
		return 0, err
	}
	helper, err := createInteractiveProcess(token, `winsta0\default`, executable, args)
	if err != nil {
		return 0, err
	}
	if code, completed := helper.wait(15 * time.Second); completed {
		return code, nil
	}
	helper.terminate(2 * time.Second)
	return 0, errors.New("drive command timed out")
}

func syncWardenHomeJob(p map[string]interface{}) (int, string, error) {
	username, _ := p["username"].(string)
	if !identityUsernamePattern.MatchString(username) {
		return 1, "", errors.New("invalid Warden Home username")
	}
	home, ok := p["home"]
	if refresh, _ := p["refresh"].(bool); refresh {
		result, err := apiPost("/api/agent/home-config", map[string]interface{}{"username": username}, true, 30)
		if err != nil {
			return 1, "", fmt.Errorf("refresh Warden Home configuration: %w", err)
		}
		if result == nil {
			return 1, "", errors.New("Warden returned an empty Home configuration")
		}
		home, ok = result["home"]
	}
	if !ok {
		return 1, "", errors.New("missing signed Warden Home configuration")
	}
	report, syncErr := syncWardenHomeWithReport(username, home)
	output, err := json.Marshal(report)
	if err != nil {
		return 1, "", err
	}
	if syncErr != nil {
		return 1, string(output), syncErr
	}
	return 0, string(output), nil
}

// Keep bytes imported in old Go toolchains where io.Discard optimization may
// be build-tagged differently by downstream packagers.
var _ = bytes.MinRead
