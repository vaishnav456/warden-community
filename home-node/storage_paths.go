package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

func acquireSpaceLock(prefix string) (func(), error) {
	if strings.TrimSpace(cfg.StorageClusterID) == "" {
		return func() {}, nil
	}
	lockRoot := filepath.Join(cfg.Root, ".warden-locks")
	if err := os.MkdirAll(lockRoot, 0700); err != nil {
		return nil, err
	}
	digest := sha256.Sum256([]byte(cfg.StorageClusterID + "\x00" + prefix))
	lockPath := filepath.Join(lockRoot, hex.EncodeToString(digest[:]))
	deadline := time.Now().Add(30 * time.Second)
	for {
		if err := os.Mkdir(lockPath, 0700); err == nil {
			_ = os.WriteFile(filepath.Join(lockPath, "owner"), []byte(cfg.NodeID), 0600)
			stopRefresh := make(chan struct{})
			go func() {
				ticker := time.NewTicker(time.Minute)
				defer ticker.Stop()
				for {
					select {
					case <-ticker.C:
						now := time.Now()
						_ = os.Chtimes(lockPath, now, now)
					case <-stopRefresh:
						return
					}
				}
			}()
			return sync.OnceFunc(func() {
				close(stopRefresh)
				_ = os.RemoveAll(lockPath)
			}), nil
		} else if !os.IsExist(err) {
			return nil, err
		}
		if info, err := os.Stat(lockPath); err == nil && time.Since(info.ModTime()) > 15*time.Minute {
			_ = os.RemoveAll(lockPath)
			continue
		}
		if time.Now().After(deadline) {
			return nil, errors.New("shared storage is busy")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func cleanRelative(value string) (string, error) {
	value = strings.ReplaceAll(strings.TrimSpace(value), "\\", "/")
	value = strings.TrimPrefix(value, "/")
	clean := filepath.ToSlash(filepath.Clean(value))
	if clean == "." || clean == "" || strings.HasPrefix(clean, "../") || strings.Contains(clean, "/../") || filepath.IsAbs(clean) {
		return "", errors.New("invalid relative path")
	}
	return clean, nil
}

func pathsFor(rel string) (string, string, error) {
	clean, err := cleanRelative(rel)
	if err != nil {
		return "", "", err
	}
	root, err := filepath.Abs(cfg.Root)
	if err != nil {
		return "", "", err
	}
	data := filepath.Join(root, filepath.FromSlash(clean)+".whome")
	full, err := filepath.Abs(data)
	if err != nil {
		return "", "", err
	}
	if full != root && !strings.HasPrefix(strings.ToLower(full), strings.ToLower(root+string(os.PathSeparator))) {
		return "", "", errors.New("path escape")
	}
	// Lexical containment is not enough when an attacker can place a symlink
	// below the storage root. Reject every existing symlink component,
	// including the final encrypted file, before opening it.
	relToRoot, err := filepath.Rel(root, full)
	if err != nil {
		return "", "", err
	}
	cursor := root
	for _, component := range strings.Split(relToRoot, string(os.PathSeparator)) {
		cursor = filepath.Join(cursor, component)
		info, statErr := os.Lstat(cursor)
		if statErr != nil {
			if os.IsNotExist(statErr) {
				break
			}
			return "", "", statErr
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", "", errors.New("symlink paths are not permitted")
		}
	}
	return full, full + ".meta", nil
}

func diskUsage() (int64, int64) {
	var used int64
	_ = filepath.Walk(cfg.Root, func(_ string, info os.FileInfo, err error) error {
		if err == nil && info != nil && !info.IsDir() {
			used += info.Size()
		}
		return nil
	})
	return 0, used
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".warden-home-identity-")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err == nil {
		return nil
	}
	// Windows cannot replace an existing file with os.Rename. The previous
	// certificate remains loaded by the running server until the complete new
	// pair has been validated and written.
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return os.Rename(name, path)
}
