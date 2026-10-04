package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type fileEntry struct {
	Deleted bool   `json:"deleted,omitempty"`
	Path    string `json:"path"`
	Size    int64  `json:"size"`
	ModTime int64  `json:"mtime"`
	SHA256  string `json:"sha256,omitempty"`
	IsDir   bool   `json:"is_dir,omitempty"`
}

type metadata struct {
	Size    int64  `json:"Size"`
	ModTime int64  `json:"ModTime"`
	Auth    string `json:"Auth,omitempty"`
	SHA256  string `json:"SHA256,omitempty"`
	Valid   bool   `json:"-"`
	Exists  bool   `json:"-"`
}

func prefixUsage(prefix string) int64 {
	data, _, err := pathsFor(prefix)
	if err != nil {
		return 0
	}
	root := strings.TrimSuffix(data, ".whome")
	var used int64
	walkResult := filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr == nil && info != nil && !info.IsDir() && strings.HasSuffix(path, ".whome.meta") {
			m := loadMeta(path)
			if !m.Valid {
				return errors.New("invalid authenticated metadata")
			}
			if used > math.MaxInt64-m.Size {
				return errors.New("storage usage overflow")
			}
			used += m.Size
		}
		return nil
	})
	if walkResult != nil {
		return math.MaxInt64
	}
	historyBytes, err := historyUsageAndCleanup(prefix, false)
	if err != nil || used > math.MaxInt64-historyBytes {
		return math.MaxInt64
	}
	used += historyBytes
	return used
}

func loadMeta(path string) metadata {
	raw, err := os.ReadFile(path)
	if err != nil {
		return metadata{Valid: os.IsNotExist(err), Exists: false}
	}
	var m metadata
	m.Exists = true
	if json.Unmarshal(raw, &m) != nil || m.Size < 0 {
		return m
	}
	dataPath := strings.TrimSuffix(path, ".meta")
	data, err := os.Open(dataPath)
	if err != nil {
		return m
	}
	header := make([]byte, len(magic))
	_, headerErr := io.ReadFull(data, header)
	data.Close()
	if headerErr != nil {
		return m
	}
	if m.Auth == "" {
		m.Valid = string(header) == magic && m.SHA256 == ""
		return m
	}
	rel, err := filepath.Rel(cfg.Root, strings.TrimSuffix(dataPath, ".whome"))
	if err != nil {
		return m
	}
	auth, err := base64.RawURLEncoding.DecodeString(m.Auth)
	if err != nil || len(auth) != aead.NonceSize()+aead.Overhead() {
		return m
	}
	nonce, tag := auth[:aead.NonceSize()], auth[aead.NonceSize():]
	_, err = aead.Open(nil, nonce, tag, metadataHashAAD(filepath.ToSlash(rel), m))
	m.Valid = err == nil && string(header) == magicV2
	return m
}

func listStoredFiles(prefix string) ([]fileEntry, error) {
	return listStoredEntries(prefix, false)
}

func listStoredEntries(prefix string, includeDirectories bool) ([]fileEntry, error) {
	root, _, err := pathsFor(prefix)
	if err != nil {
		return nil, err
	}
	root = strings.TrimSuffix(root, ".whome")
	var entries []fileEntry
	err = filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			if os.IsNotExist(walkErr) {
				return nil
			}
			return walkErr
		}
		if info == nil {
			return nil
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("symlink storage paths are not permitted")
		}
		if info.IsDir() {
			if strings.HasSuffix(path, ".whome.history") && isHomeHistoryDirectory(path) {
				return filepath.SkipDir
			}
			if includeDirectories && path != root {
				rel, err := filepath.Rel(cfg.Root, path)
				if err != nil {
					return err
				}
				entries = append(entries, fileEntry{Path: filepath.ToSlash(rel), IsDir: true})
			}
			return nil
		}
		if !strings.HasSuffix(path, ".whome") {
			return nil
		}
		rel, err := filepath.Rel(cfg.Root, strings.TrimSuffix(path, ".whome"))
		if err != nil {
			return nil
		}
		if deletion, err := readHomeDeletion(filepath.ToSlash(rel)); err != nil {
			return err
		} else if deletion != nil {
			return nil
		}
		m := loadMeta(path + ".meta")
		if !m.Valid {
			return errors.New("stored file metadata authentication failed")
		}
		digest := m.SHA256
		if digest == "" {
			f, err := os.Open(path)
			if err != nil {
				return err
			}
			h := sha256.New()
			err = decryptStreamForPath(h, f, filepath.ToSlash(rel))
			f.Close()
			if err != nil {
				return err
			}
			digest = hex.EncodeToString(h.Sum(nil))
		}
		entries = append(entries, fileEntry{Path: filepath.ToSlash(rel), Size: m.Size, ModTime: m.ModTime, SHA256: digest})
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	return entries, nil
}
