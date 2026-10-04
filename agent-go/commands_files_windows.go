package main

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const maxRemoteTransferBytes = 8 * 1024 * 1024

// ── File operations ───────────────────────────────────────────────────────────

func filePush(p map[string]interface{}) (int, string, error) {
	destPath, _ := p["path"].(string)
	contentB64, _ := p["content_b64"].(string)
	if destPath == "" || contentB64 == "" {
		return 1, "", fmt.Errorf("missing path or content_b64")
	}
	// Reject oversized input before DecodeString allocates its destination.
	// The payload is server-signed, but a configuration mistake should not be
	// able to exhaust memory in the SYSTEM service.
	if int64(len(contentB64)) > (maxRemoteTransferBytes*4/3)+4 {
		return 1, "", fmt.Errorf("file is too large for remote transfer (max 8 MB)")
	}
	safeRoots := []string{
		`c:\programdata\wardenagent\`,
		`c:\windows\temp\`,
		`c:\users\public\`,
		// Remote-view drag-and-drop may target the active Explorer folder
		// within a user's profile instead of always forcing Public Desktop.
		// resolveAllowedPath still canonicalizes the destination and prevents
		// traversal outside C:\Users.
		`c:\users\`,
	}
	destPath, err := resolveAllowedPath(destPath, safeRoots)
	if err != nil {
		return 1, "", err
	}
	content, err := base64.StdEncoding.DecodeString(contentB64)
	if err != nil {
		return 1, "", fmt.Errorf("base64 decode: %w", err)
	}
	if int64(len(content)) > maxRemoteTransferBytes {
		return 1, "", fmt.Errorf("file is too large for remote transfer (max 8 MB)")
	}
	os.MkdirAll(filepath.Dir(destPath), 0700)
	if err := os.WriteFile(destPath, content, 0600); err != nil {
		return 1, "", fmt.Errorf("write file: %w", err)
	}
	return 0, fmt.Sprintf("File written to %s (%d bytes)", destPath, len(content)), nil
}

func filePull(jobID string, p map[string]interface{}) (int, string, error) {
	srcPath, _ := p["path"].(string)
	if srcPath == "" {
		return 1, "", fmt.Errorf("missing path")
	}
	safeRoots := []string{
		`c:\programdata\wardenagent\`,
		`c:\windows\logs\`,
		`c:\windows\temp\`,
		`c:\users\public\`,
		// Remote-view downloads may select a file in the interactive user's
		// profile. resolveAllowedPath canonicalizes it and prevents escaping
		// C:\Users through traversal.
		`c:\users\`,
	}
	srcPath, err := resolveAllowedPath(srcPath, safeRoots)
	if err != nil {
		return 1, "", err
	}
	info, err := os.Stat(srcPath)
	if err != nil {
		return 1, "", fmt.Errorf("stat file: %w", err)
	}
	var content []byte
	downloadName := filepath.Base(srcPath)
	if info.IsDir() {
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		err = filepath.Walk(srcPath, func(path string, entry os.FileInfo, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				return nil
			}
			if !entry.Mode().IsRegular() {
				return nil
			}
			rel, relErr := filepath.Rel(srcPath, path)
			if relErr != nil {
				return relErr
			}
			w, createErr := zw.Create(filepath.ToSlash(rel))
			if createErr != nil {
				return createErr
			}
			f, openErr := os.Open(path)
			if openErr != nil {
				return openErr
			}
			_, copyErr := io.Copy(w, io.LimitReader(f, maxRemoteTransferBytes+1))
			f.Close()
			if copyErr != nil {
				return copyErr
			}
			if buf.Len() > maxRemoteTransferBytes {
				return fmt.Errorf("folder is too large for remote transfer (max 8 MB compressed)")
			}
			return nil
		})
		closeErr := zw.Close()
		if err != nil {
			return 1, "", err
		}
		if closeErr != nil {
			return 1, "", closeErr
		}
		content = buf.Bytes()
		downloadName += ".zip"
	} else if info.Mode().IsRegular() {
		if info.Size() > maxRemoteTransferBytes {
			return 1, "", fmt.Errorf("file is too large for remote transfer (max 8 MB)")
		}
		content, err = os.ReadFile(srcPath)
		if err != nil {
			return 1, "", fmt.Errorf("read file: %w", err)
		}
	} else {
		return 1, "", fmt.Errorf("path is not a regular file or folder")
	}
	if len(content) > maxRemoteTransferBytes {
		return 1, "", fmt.Errorf("file is too large for remote transfer (max 8 MB)")
	}
	contentB64 := base64.StdEncoding.EncodeToString(content)
	// The pulled bytes only ever exist in this POST -- log_output below is
	// just a summary sentence, not the actual file content. Discarding this
	// error used to mean a failed delivery still reported job success with
	// a plausible-looking message, silently losing the file.
	if _, err := apiPostAuth("/api/agent/file-content", map[string]interface{}{
		"job_id":        jobID,
		"path":          srcPath,
		"download_name": downloadName,
		"content_b64":   contentB64,
		"size_bytes":    len(content),
	}); err != nil {
		return 1, "", fmt.Errorf("report file content: %w", err)
	}
	return 0, fmt.Sprintf("File %s pulled (%d bytes)", srcPath, len(content)), nil
}

func listDirectory(p map[string]interface{}) (int, string, error) {
	dirPath, _ := p["path"].(string)
	type item struct {
		Name  string `json:"name"`
		Path  string `json:"path"`
		IsDir bool   `json:"is_dir"`
		Size  int64  `json:"size"`
	}
	roots := remoteUserFolderRoots()
	if dirPath == "" || dirPath == "::folders::" {
		items := make([]item, 0, len(roots))
		for _, root := range roots {
			items = append(items, item{
				Name: filepath.Base(filepath.Dir(root)) + " — " + filepath.Base(root),
				Path: root, IsDir: true,
			})
		}
		result, _ := json.Marshal(map[string]interface{}{"path": "::folders::", "items": items})
		return 0, string(result), nil
	}
	resolved, err := resolveAllowedPath(dirPath, roots)
	if err != nil {
		return 1, "", err
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.IsDir() {
		return 1, "", fmt.Errorf("folder not found")
	}
	entries, err := os.ReadDir(resolved)
	if err != nil {
		return 1, "", err
	}
	const maxDirectoryEntries = 2000
	truncated := len(entries) > maxDirectoryEntries
	if truncated {
		entries = entries[:maxDirectoryEntries]
	}
	items := make([]item, 0, len(entries))
	for _, entry := range entries {
		child := filepath.Join(resolved, entry.Name())
		entryInfo, infoErr := entry.Info()
		if infoErr != nil {
			continue
		}
		items = append(items, item{entry.Name(), child, entry.IsDir(), entryInfo.Size()})
	}
	result, _ := json.Marshal(map[string]interface{}{
		"path": resolved, "items": items, "truncated": truncated,
	})
	return 0, string(result), nil
}

func remoteUserFolderRoots() []string {
	profiles, _ := os.ReadDir(`C:\Users`)
	var roots []string
	for _, profile := range profiles {
		if !profile.IsDir() {
			continue
		}
		for _, folder := range []string{"Desktop", "Documents", "Downloads"} {
			path := filepath.Join(`C:\Users`, profile.Name(), folder)
			if info, err := os.Stat(path); err == nil && info.IsDir() {
				roots = append(roots, path)
			}
		}
	}
	return roots
}

var canonicalJobID = regexp.MustCompile(
	`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`,
)

func jobStageDir(jobID string) (string, error) {
	if !canonicalJobID.MatchString(jobID) {
		return "", fmt.Errorf("job_id must be a canonical UUID")
	}
	return filepath.Join(stagingDir, strings.ToLower(jobID)), nil
}

func resolveAllowedPath(path string, roots []string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("path must be absolute")
	}
	cleaned, err := canonicalPath(path)
	if err != nil {
		return "", fmt.Errorf("canonicalize path: %w", err)
	}
	for _, root := range roots {
		rootAbs, err := canonicalPath(root)
		if err != nil {
			continue
		}
		rel, err := filepath.Rel(rootAbs, cleaned)
		if err == nil && rel != ".." &&
			!strings.HasPrefix(rel, `..\`) && !filepath.IsAbs(rel) {
			return cleaned, nil
		}
	}
	return "", fmt.Errorf("path outside allowed locations: %s", path)
}

func canonicalPath(path string) (string, error) {
	absolute, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return "", err
	}
	current := absolute
	var suffix []string
	for {
		if _, statErr := os.Stat(current); statErr == nil {
			resolved, err := filepath.EvalSymlinks(current)
			if err != nil {
				return "", err
			}
			for i := len(suffix) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, suffix[i])
			}
			return filepath.Clean(resolved), nil
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", fmt.Errorf("no existing ancestor for %s", path)
		}
		suffix = append(suffix, filepath.Base(current))
		current = parent
	}
}
