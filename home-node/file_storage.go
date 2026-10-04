package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var errFileTooLarge = errors.New("file too large")

func writeFile(rel string, src io.Reader, mtime, maxBytes int64) error {
	return writeFileVerified(rel, src, mtime, maxBytes, "")
}

func writeFileVerified(rel string, src io.Reader, mtime, maxBytes int64, expectedSHA256 string) error {
	data, meta, err := pathsFor(rel)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(data), 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(data), ".warden-home-")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if maxBytes <= 0 || maxBytes > 5*1024*1024*1024 {
		maxBytes = 5 * 1024 * 1024 * 1024
	}
	digest := sha256.New()
	size, err := encryptStreamForPath(tmp, io.TeeReader(io.LimitReader(src, maxBytes+1), digest), rel)
	closeErr := tmp.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if size > maxBytes {
		return errFileTooLarge
	}
	contentHash := hex.EncodeToString(digest.Sum(nil))
	if expectedSHA256 != "" && !strings.EqualFold(expectedSHA256, contentHash) {
		return errors.New("replicated content hash mismatch")
	}
	if err := os.Rename(name, data); err != nil {
		// Windows cannot atomically replace an existing destination. The
		// encrypted temporary file is already complete and authenticated.
		if removeErr := os.Remove(data); removeErr != nil && !os.IsNotExist(removeErr) {
			return err
		}
		if err := os.Rename(name, data); err != nil {
			return err
		}
	}
	if mtime == 0 {
		mtime = time.Now().Unix()
	}
	m := metadata{Size: size, ModTime: mtime, SHA256: contentHash, Valid: true, Exists: true}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	tag := aead.Seal(nil, nonce, nil, metadataHashAAD(rel, m))
	m.Auth = base64.RawURLEncoding.EncodeToString(append(nonce, tag...))
	raw, _ := json.Marshal(m)
	return atomicWrite(meta, raw, 0600)
}

func storeAuthorizedFile(rel string, src io.Reader, mtime int64, g grant) (int, error) {
	return storeAuthorizedFileVerified(rel, src, mtime, g, "")
}

func storeAuthorizedFileVerified(rel string, src io.Reader, mtime int64, g grant, expectedSHA256 string, readdVersion ...string) (int, error) {
	deletion, err := readHomeDeletion(rel)
	if err != nil {
		return http.StatusInternalServerError, err
	} else if deletion != nil {
		if len(readdVersion) == 0 || readdVersion[0] != homeDeletionVersion(deletion) {
			return http.StatusConflict, errors.New("file was intentionally deleted; stale upload refused")
		}
		if err := purgeHomeDeletion(rel); err != nil {
			return http.StatusInternalServerError, err
		}
	}
	maxBytes := g.MaxFileBytes
	if _, err := historyUsageAndCleanup(g.Prefix, true); err != nil {
		return 500, err
	}
	if maxBytes <= 0 || maxBytes > 5*1024*1024*1024 {
		maxBytes = 5 * 1024 * 1024 * 1024
	}
	allowed := maxBytes
	quotaLimited := false
	if g.QuotaBytes > 0 {
		_, metaPath, err := pathsFor(rel)
		if err != nil {
			return http.StatusBadRequest, err
		}
		existing := loadMeta(metaPath)
		if existing.Exists && !existing.Valid {
			return http.StatusInternalServerError, errors.New("stored file metadata authentication failed")
		}
		usage := prefixUsage(g.Prefix)
		if usage == math.MaxInt64 {
			return http.StatusInternalServerError, errors.New("storage usage cannot be authenticated")
		}
		remaining := g.QuotaBytes - usage + existing.Size
		growth, err := historyGrowth(rel, g.HistoryDays)
		if err != nil {
			return 500, err
		}
		remaining -= growth
		if remaining < allowed {
			allowed, quotaLimited = remaining, true
		}
		if allowed < 0 {
			allowed = 0
		}
		if allowed == 0 {
			return http.StatusInsufficientStorage, errFileTooLarge
		}
	}
	if err := archiveHomeVersion(rel, g.HistoryDays, false); err != nil {
		return 500, err
	}
	if err := writeFileVerified(rel, src, mtime, allowed, expectedSHA256); err != nil {
		if errors.Is(err, errFileTooLarge) {
			if quotaLimited {
				return http.StatusInsufficientStorage, err
			}
			return http.StatusRequestEntityTooLarge, err
		}
		return http.StatusInternalServerError, err
	}
	if deletion != nil {
		data, _, err := pathsFor(rel)
		if err != nil {
			return http.StatusInternalServerError, err
		}
		if err := os.Remove(data + ".deleted"); err != nil {
			return http.StatusInternalServerError, err
		}
	}
	return http.StatusNoContent, nil
}
