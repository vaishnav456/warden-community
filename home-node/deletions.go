package main

// Deletion markers are encrypted and authenticated with the Home storage key.
// Retain encrypted data for recovery, but never serve/list it as an active file.
import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type homeDeletion struct {
	SHA256    string `json:"sha256"`
	Size      int64  `json:"size"`
	DeletedAt int64  `json:"deleted_at"`
}

func deletionAAD(rel string) []byte {
	return []byte("warden-home:deletion:v1:" + filepath.ToSlash(rel))
}

func readHomeDeletion(rel string) (*homeDeletion, error) {
	clean, err := cleanRelative(rel)
	if err != nil {
		return nil, err
	}
	rel = clean
	data, _, err := pathsFor(rel)
	if err != nil {
		return nil, err
	}
	marker := data + ".deleted"
	info, err := os.Lstat(marker)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > 65536 {
		return nil, errors.New("invalid deletion marker")
	}
	raw, err := os.ReadFile(marker)
	if err != nil {
		return nil, err
	}
	if len(raw) < aead.NonceSize()+aead.Overhead() {
		return nil, errors.New("invalid deletion marker")
	}
	plain, err := aead.Open(nil, raw[:aead.NonceSize()], raw[aead.NonceSize():], deletionAAD(rel))
	if err != nil {
		return nil, err
	}
	var deletion homeDeletion
	if json.Unmarshal(plain, &deletion) != nil || len(deletion.SHA256) != 64 || deletion.DeletedAt <= 0 || deletion.Size < 0 {
		return nil, errors.New("invalid deletion record")
	}
	return &deletion, nil
}

func writeHomeDeletion(rel string, deletion homeDeletion) error {
	clean, err := cleanRelative(rel)
	if err != nil {
		return err
	}
	rel = clean
	data, _, err := pathsFor(rel)
	if err != nil {
		return err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	plain, err := json.Marshal(deletion)
	if err != nil {
		return err
	}
	return atomicWrite(data+".deleted", aead.Seal(nonce, nonce, plain, deletionAAD(rel)), 0600)
}

// Caller holds storageMu and the cross-process space lock. Compare-and-delete
// refuses to delete content that changed after the user saw the confirmation.
func confirmHomeDeletion(rel, expected string) (int, error) {
	previous, err := readHomeDeletion(rel)
	if err != nil {
		return 500, err
	}
	if previous != nil {
		if expected != "" && !strings.EqualFold(expected, previous.SHA256) {
			return 412, errors.New("deleted version changed")
		}
		return 204, nil
	}
	data, meta, err := pathsFor(rel)
	if err != nil {
		return 400, err
	}
	m := loadMeta(meta)
	if !m.Exists {
		return 404, os.ErrNotExist
	}
	if !m.Valid {
		return 500, errors.New("unauthenticated metadata")
	}
	digest := m.SHA256
	if digest == "" {
		f, err := os.Open(data)
		if err != nil {
			return 500, err
		}
		digest, err = plaintextDigest(f, rel)
		f.Close()
		if err != nil {
			return 500, err
		}
	}
	if expected != "" && !strings.EqualFold(expected, digest) {
		return 412, errors.New("remote file changed; deletion not applied")
	}
	if err := writeHomeDeletion(rel, homeDeletion{SHA256: digest, Size: m.Size, DeletedAt: time.Now().Unix()}); err != nil {
		return 500, err
	}
	return http.StatusNoContent, nil
}

func appendHomeDeletions(prefix string, entries []fileEntry) ([]fileEntry, error) {
	data, _, err := pathsFor(prefix)
	if err != nil {
		return nil, err
	}
	root := strings.TrimSuffix(data, ".whome")
	err = filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if os.IsNotExist(walkErr) {
			return nil
		}
		if walkErr != nil {
			return walkErr
		}
		if info == nil || info.IsDir() || !strings.HasSuffix(path, ".whome.deleted") {
			return nil
		}
		rel, err := filepath.Rel(cfg.Root, strings.TrimSuffix(path, ".whome.deleted"))
		if err != nil {
			return err
		}
		deletion, err := readHomeDeletion(filepath.ToSlash(rel))
		if err != nil {
			return err
		}
		if deletion != nil {
			entries = append(entries, fileEntry{Path: filepath.ToSlash(rel), Size: deletion.Size, ModTime: deletion.DeletedAt, SHA256: deletion.SHA256, Deleted: true})
		}
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("list deletion records: %w", err)
	}
	return entries, nil
}

// Used only for old authenticated files without a stored content digest.
func plaintextDigest(src io.Reader, rel string) (string, error) {
	h := sha256.New()
	if err := decryptStreamForPath(h, src, rel); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}
