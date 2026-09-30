package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

func homeContentMatches(client *http.Client, node homeNode, remote homeRemoteFile, path string, info os.FileInfo) (bool, error) {
	if !info.Mode().IsRegular() {
		return false, errors.New("sync destination is not a regular file")
	}
	if info.Size() != remote.Size {
		return false, nil
	}
	digest := remote.SHA256
	if digest == "" {
		// Older nodes cannot provide a manifest digest. Read the remote content
		// rather than incorrectly treating equal size/timestamps as equality.
		resp, err := homeRequest(client, node, http.MethodGet, remote.Path, nil, 0)
		if err != nil {
			return false, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return false, fmt.Errorf("home hash HTTP %d", resp.StatusCode)
		}
		h := sha256.New()
		n, err := io.Copy(h, io.LimitReader(resp.Body, remote.Size+1))
		if err != nil {
			return false, err
		}
		if n != remote.Size {
			return false, errors.New("incomplete remote content while checking hash")
		}
		digest = hex.EncodeToString(h.Sum(nil))
	}
	decoded, err := hex.DecodeString(digest)
	if err != nil || len(decoded) != sha256.Size {
		return false, errors.New("invalid remote SHA-256 digest")
	}
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return false, err
	}
	return strings.EqualFold(hex.EncodeToString(h.Sum(nil)), digest), nil
}

func createRemoteHomeDirectory(client *http.Client, node homeNode, path string) error {
	req, err := http.NewRequest(http.MethodPut, homeNodeURL(node)+"/v1/directory?path="+url.QueryEscape(path), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+node.Grant)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("home folder HTTP %d (update the Home Node if folder sync is unsupported)", resp.StatusCode)
	}
	return nil
}

// Reject existing symlink/junction components, including the final directory.
func validateHomeLocalPath(root, path string) error {
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return errors.New("home path escaped local folder")
	}
	cursor := root
	for _, part := range append([]string{""}, strings.Split(rel, string(os.PathSeparator))...) {
		cursor = filepath.Join(cursor, part)
		info, err := os.Lstat(cursor)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("symlink sync paths are not permitted")
		}
	}
	return nil
}
