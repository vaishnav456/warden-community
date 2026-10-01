package main

// Deletion markers are encrypted and authenticated with the Home storage key.
// Keep only the deletion record to prevent stale uploads; remove file contents.
import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
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

func homeDeletionVersion(deletion *homeDeletion) string {
	return fmt.Sprintf("%s:%d", deletion.SHA256, deletion.DeletedAt)
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
	// Persist the marker FIRST so a failed cleanup cannot resurrect the file.
	if err := atomicWrite(data+".deleted", aead.Seal(nonce, nonce, plain, deletionAAD(rel)), 0600); err != nil {
		return err
	}
	return purgeHomeDeletion(rel)
}

// Caller holds storageMu and the space lock. Never remove the tombstone: other
// endpoints still need it to distinguish intentional deletion from missing data.
func purgeHomeDeletion(rel string) error {
	deletion, err := readHomeDeletion(rel)
	if err != nil || deletion == nil {
		return err
	}
	data, meta, err := pathsFor(rel)
	if err != nil {
		return err
	}
	for _, path := range []string{data, meta} {
		info, err := os.Lstat(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return errors.New("invalid deleted file storage path")
		}
	}
	for _, path := range []string{data, meta} {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove deleted Home file: %w", err)
		}
	}
	return nil
}

// Upgrade repair: previously confirmed deletions retained encrypted contents.
// Authenticate every marker before cleanup; unmarked files are never touched.
func cleanupHomeDeletions(prefix string) error {
	entries, err := appendHomeDeletions(prefix, nil)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if err := purgeHomeDeletion(entry.Path); err != nil {
			return err
		}
	}
	return nil
}

// Caller holds storageMu and the cross-process space lock. Compare-and-delete
// refuses to delete content that changed after the user saw the confirmation.
func confirmHomeDeletion(rel, expected string, grants ...grant) (int, error) {
	previous, err := readHomeDeletion(rel)
	if err != nil {
		return 500, err
	}
	if previous != nil {
		if expected != "" && !strings.EqualFold(expected, previous.SHA256) {
			return 412, errors.New("deleted version changed")
		}
		if err := purgeHomeDeletion(rel); err != nil {
			return 500, err
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
	if len(grants) > 0 {
		g := grants[0]
		if _, err := historyUsageAndCleanup(g.Prefix, true); err != nil {
			return 500, err
		}
		growth, err := historyGrowth(rel, g.HistoryDays)
		if err != nil {
			return 500, err
		}
		used := prefixUsage(g.Prefix)
		if used == math.MaxInt64 || used < m.Size || growth > math.MaxInt64-(used-m.Size) {
			return 500, errors.New("storage usage cannot be authenticated")
		}
		if g.QuotaBytes > 0 && used-m.Size+growth > g.QuotaBytes {
			return 507, errors.New("recycle history exceeds space quota")
		}
		if err := archiveHomeVersion(rel, g.HistoryDays, true); err != nil {
			return 500, err
		}
	}
	if err := writeHomeDeletion(rel, homeDeletion{SHA256: digest, Size: m.Size, DeletedAt: time.Now().UnixNano()}); err != nil {
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
