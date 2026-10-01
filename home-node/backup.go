package main

// Independently located, immutable snapshots. Every object and the manifest
// are authenticated/encrypted; no keys or configuration credentials are copied.
import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type backupObject struct {
	Path   string
	ID     string
	Size   int64
	SHA256 string
}
type backupManifest struct {
	Version     int
	ID          string
	KeyID       string
	CreatedAt   string
	Directories []string
	Objects     []backupObject
}
type backupSummary struct {
	Configured bool   `json:"configured"`
	Status     string `json:"status"`
	SnapshotID string `json:"snapshot_id,omitempty"`
	VerifiedAt string `json:"verified_at,omitempty"`
	Files      int    `json:"files"`
	Bytes      int64  `json:"bytes"`
	Error      string `json:"error,omitempty"`
}

var backupMu sync.Mutex
var backupStateMu sync.Mutex
var backupState backupSummary

func backupStatus() backupSummary {
	backupStateMu.Lock()
	defer backupStateMu.Unlock()
	result := backupState
	result.Configured = cfg.BackupRoot != ""
	return result
}
func recordBackup(result backupSummary, err error) {
	result.Configured = cfg.BackupRoot != ""
	if err != nil {
		result.Status = "failed"
		result.Error = "Backup or verification failed; inspect the node log."
	}
	backupStateMu.Lock()
	if err != nil {
		result.SnapshotID = backupState.SnapshotID
		result.VerifiedAt = backupState.VerifiedAt
		result.Files = backupState.Files
		result.Bytes = backupState.Bytes
	}
	backupState = result
	backupStateMu.Unlock()
}
func randomBackupID() (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	return hex.EncodeToString(b), err
}
func validBackupID(id string) bool {
	b, err := hex.DecodeString(id)
	return err == nil && len(b) == 16 && id == strings.ToLower(id)
}
func insideDirectory(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}
func absoluteRealDirectory(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", errors.New("backup/recovery paths must be absolute")
	}
	clean := filepath.Clean(path)
	// Refuse symlink/reparse ancestors, even when the leaf does not yet exist.
	for p := clean; ; p = filepath.Dir(p) {
		info, err := os.Lstat(p)
		if err == nil && (info.Mode()&os.ModeSymlink != 0 || !info.IsDir()) {
			return "", errors.New("symbolic or non-directory backup path")
		}
		if err != nil && !os.IsNotExist(err) {
			return "", err
		}
		if filepath.Dir(p) == p {
			break
		}
	}
	return clean, nil
}
func backupDestination() (string, error) {
	root, err := filepath.Abs(cfg.Root)
	if err != nil {
		return "", err
	}
	dest, err := absoluteRealDirectory(cfg.BackupRoot)
	if err != nil {
		return "", err
	}
	if insideDirectory(root, dest) || insideDirectory(dest, root) {
		return "", errors.New("backup destination must be separate from the active Home root")
	}
	if cfg.BackupMaxBytes <= 0 {
		return "", errors.New("configure a positive backup_max_bytes before enabling backups")
	}
	if cfg.StorageClusterID != "" {
		return "", errors.New("shared active-active stores require a coordinated offline/external snapshot")
	}
	return dest, nil
}
func backupUsage(root string) (int64, error) {
	var total int64
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("symbolic path in backup destination")
		}
		if !info.IsDir() {
			if info.Size() > cfg.BackupMaxBytes-total {
				return errors.New("backup destination quota exhausted")
			}
			total += info.Size()
		}
		return nil
	})
	return total, err
}
func backupAAD(id, object string) string { return "warden-backup/" + id + "/" + object }

// Called under storageMu. Pin immutable encrypted inodes on the same filesystem,
// then release the lock before hashing, copying or verifying large file data.
// Metadata is published by atomic replacement, never modified in place.
func captureBackupSource() (string, error) {
	snapshot, err := os.MkdirTemp(cfg.Root, ".warden-backup-source-")
	if err != nil {
		return "", err
	}
	success := false
	defer func() {
		if !success {
			_ = os.RemoveAll(snapshot)
		}
	}()
	count := 0
	deadline := time.Now().Add(30 * time.Second)
	err = filepath.Walk(cfg.Root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if time.Now().After(deadline) {
			return errors.New("backup source capture exceeded 30 seconds")
		}
		rel, err := filepath.Rel(cfg.Root, path)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("symbolic path in Home root")
		}
		if info.IsDir() {
			if rel == ".warden-locks" || rel == ".warden-package-cache" || strings.HasPrefix(rel, ".warden-backup-source-") {
				return filepath.SkipDir
			}
			if rel == "." {
				return nil
			}
			count++
			if count > 200000 {
				return errors.New("backup source limit exceeded")
			}
			return os.MkdirAll(filepath.Join(snapshot, rel), 0700)
		}
		if !info.Mode().IsRegular() {
			return errors.New("non-regular Home object")
		}
		if strings.HasSuffix(rel, ".tmp") || strings.Contains(rel, ".tmp-") || rel == ".warden-restore-incomplete" {
			return errors.New("incomplete Home write or restore")
		}
		if !strings.HasSuffix(rel, ".whome") && !strings.HasSuffix(rel, ".whome.meta") &&
			!strings.HasSuffix(rel, ".whome.deleted") && !isHomeHistoryDirectory(filepath.Dir(path)) {
			return nil
		}
		count++
		if count > 200000 {
			return errors.New("backup source limit exceeded")
		}
		// No fallback to an unbounded copy while holding the storage lock.
		return os.Link(path, filepath.Join(snapshot, rel))
	})
	if err != nil {
		return "", err
	}
	success = true
	return snapshot, nil
}

func createBackup() (backupSummary, error) {
	backupMu.Lock()
	defer backupMu.Unlock()
	result := backupSummary{Status: "creating"}
	dest, err := backupDestination()
	if err != nil {
		return result, err
	}
	if err = os.MkdirAll(dest, 0700); err != nil {
		return result, err
	}
	used, err := backupUsage(dest)
	if err != nil {
		return result, err
	}
	id, err := randomBackupID()
	if err != nil {
		return result, err
	}
	stage := filepath.Join(dest, "."+id+".partial")
	if err = os.Mkdir(stage, 0700); err != nil {
		return result, err
	}
	// Only our exact, freshly created staging directory is removed on failure.
	published := false
	defer func() {
		if !published {
			_ = os.RemoveAll(stage)
		}
	}()
	manifest := backupManifest{Version: 1, ID: id, KeyID: encryptionKeyID, CreatedAt: time.Now().UTC().Format(time.RFC3339)}
	storageMu.Lock()
	snapshot, err := captureBackupSource()
	storageMu.Unlock()
	if err != nil {
		return result, err
	}
	defer os.RemoveAll(snapshot)
	deadline := time.Now().Add(20 * time.Minute)
	err = filepath.Walk(snapshot, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if time.Now().After(deadline) {
			return errors.New("backup duration exceeded")
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("symbolic path in Home root")
		}
		rel, e := filepath.Rel(snapshot, path)
		if e != nil {
			return e
		}
		rel = filepath.ToSlash(rel)
		if info.IsDir() {
			if rel == ".warden-locks" || rel == ".warden-package-cache" {
				return filepath.SkipDir
			}
			if rel != "." {
				manifest.Directories = append(manifest.Directories, rel)
			}
			if len(manifest.Directories) > 100000 {
				return errors.New("snapshot directory limit exceeded")
			}
			return nil
		}
		if !info.Mode().IsRegular() {
			return errors.New("non-regular Home object")
		}
		if strings.HasSuffix(rel, ".tmp") || strings.Contains(rel, ".tmp-") || rel == ".warden-restore-incomplete" {
			return errors.New("incomplete write or restore in Home root")
		}
		isHistory := isHomeHistoryDirectory(filepath.Dir(path))
		if !strings.HasSuffix(rel, ".whome") && !strings.HasSuffix(rel, ".whome.meta") && !strings.HasSuffix(rel, ".whome.deleted") && !isHistory {
			return nil
		}
		if len(manifest.Objects) >= 100000 {
			return errors.New("snapshot object limit exceeded")
		}
		if strings.HasSuffix(rel, ".whome") {
			f, e := os.Open(path)
			if e != nil {
				return e
			}
			e = decryptStreamForPath(io.Discard, f, strings.TrimSuffix(rel, ".whome"))
			f.Close()
			if e != nil {
				return fmt.Errorf("source encrypted file failed verification: %w", e)
			}
		}
		objectID, e := randomBackupID()
		if e != nil {
			return e
		}
		estimate := info.Size() + int64((info.Size()/chunkSize+2)*(int64(aead.Overhead()+aead.NonceSize()+4))) + 128
		if estimate < info.Size() || estimate > cfg.BackupMaxBytes-used {
			return errors.New("backup destination quota exhausted")
		}
		source, e := os.Open(path)
		if e != nil {
			return e
		}
		target, e := os.OpenFile(filepath.Join(stage, objectID+".blob"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			source.Close()
			return e
		}
		digest := sha256.New()
		size, e := encryptStreamForPath(target, io.TeeReader(io.LimitReader(source, info.Size()+1), digest), backupAAD(id, objectID))
		source.Close()
		if e == nil && size != info.Size() {
			e = errors.New("source changed during backup")
		}
		if e == nil {
			e = target.Sync()
		}
		closeErr := target.Close()
		if e == nil {
			e = closeErr
		}
		if e != nil {
			return e
		}
		stored, e := os.Stat(filepath.Join(stage, objectID+".blob"))
		if e != nil {
			return e
		}
		if stored.Size() > cfg.BackupMaxBytes-used {
			return errors.New("backup destination quota exhausted")
		}
		used += stored.Size()
		result.Bytes += stored.Size()
		manifest.Objects = append(manifest.Objects, backupObject{Path: rel, ID: objectID, Size: size, SHA256: hex.EncodeToString(digest.Sum(nil))})
		return nil
	})
	if err != nil {
		return result, err
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		return result, err
	}
	if len(raw) > 32*1024*1024 {
		return result, errors.New("backup manifest too large")
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return result, err
	}
	sealed := append(nonce, aead.Seal(nil, nonce, raw, []byte(backupAAD(id, "manifest")))...)
	if int64(len(sealed)) > cfg.BackupMaxBytes-used {
		return result, errors.New("backup destination quota exhausted")
	}
	if err = os.WriteFile(filepath.Join(stage, "manifest.enc"), sealed, 0600); err != nil {
		return result, err
	}
	// Verify every object before publication. A half-finished snapshot is never selectable.
	if _, err = verifyBackupAt(stage, id, nil); err != nil {
		return result, err
	}
	if err = os.Rename(stage, filepath.Join(dest, id)); err != nil {
		return result, err
	}
	published = true
	result.Status = "verified"
	result.SnapshotID = id
	result.VerifiedAt = time.Now().UTC().Format(time.RFC3339)
	result.Files = len(manifest.Objects)
	result.Bytes += int64(len(sealed))
	return result, nil
}

func readBackupManifest(directory, id string) (backupManifest, error) {
	var manifest backupManifest
	if !validBackupID(id) {
		return manifest, errors.New("invalid snapshot ID")
	}
	path := filepath.Join(directory, "manifest.enc")
	info, err := os.Lstat(path)
	if err != nil {
		return manifest, err
	}
	if !info.Mode().IsRegular() || info.Size() > 32*1024*1024 || info.Size() < int64(aead.NonceSize()+aead.Overhead()) {
		return manifest, errors.New("invalid backup manifest")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return manifest, err
	}
	plain, err := aead.Open(nil, raw[:aead.NonceSize()], raw[aead.NonceSize():], []byte(backupAAD(id, "manifest")))
	if err != nil {
		return manifest, errors.New("backup key or manifest authentication failed")
	}
	if err = json.Unmarshal(plain, &manifest); err != nil {
		return manifest, err
	}
	if manifest.Version != 1 || manifest.ID != id || manifest.KeyID != encryptionKeyID || len(manifest.Objects) > 100000 || len(manifest.Directories) > 100000 {
		return manifest, errors.New("backup identity mismatch")
	}
	for _, directory := range manifest.Directories {
		clean, err := cleanRelative(directory)
		if err != nil || clean != directory {
			return manifest, errors.New("invalid backup directory")
		}
	}
	return manifest, nil
}
func verifyBackupAt(directory, id string, restore func(backupObject, io.Reader) error) (backupSummary, error) {
	result := backupSummary{SnapshotID: id}
	manifest, err := readBackupManifest(directory, id)
	if err != nil {
		return result, err
	}
	seen := map[string]bool{}
	for _, object := range manifest.Objects {
		path, e := cleanRelative(object.Path)
		if e != nil || path != object.Path || !validBackupID(object.ID) || seen[path] || object.Size < 0 {
			return result, errors.New("invalid backup object")
		}
		seen[path] = true
		info, e := os.Lstat(filepath.Join(directory, object.ID+".blob"))
		if e != nil {
			return result, e
		}
		if !info.Mode().IsRegular() {
			return result, errors.New("symbolic backup object")
		}
		blob, e := os.Open(filepath.Join(directory, object.ID+".blob"))
		if e != nil {
			return result, e
		}
		pipeReader, pipeWriter := io.Pipe()
		go func() {
			err := decryptStreamForPath(pipeWriter, blob, backupAAD(id, object.ID))
			blob.Close()
			pipeWriter.CloseWithError(err)
		}()
		digest := sha256.New()
		reader := io.TeeReader(pipeReader, digest)
		var size int64
		if restore != nil {
			e = restore(object, reader)
		} else {
			size, e = io.Copy(io.Discard, reader)
		}
		pipeReader.Close()
		if e != nil {
			return result, e
		}
		if restore == nil && size != object.Size {
			return result, errors.New("backup object size mismatch")
		}
		if hex.EncodeToString(digest.Sum(nil)) != object.SHA256 {
			return result, errors.New("backup object digest mismatch")
		}
		result.Files++
		result.Bytes += info.Size()
	}
	result.Status = "verified"
	result.VerifiedAt = time.Now().UTC().Format(time.RFC3339)
	return result, nil
}
func verifyBackup(id string) (backupSummary, error) {
	if !validBackupID(id) {
		return backupSummary{}, errors.New("invalid snapshot ID")
	}
	dest, err := backupDestination()
	if err != nil {
		return backupSummary{}, err
	}
	directory, err := absoluteRealDirectory(filepath.Join(dest, id))
	if err != nil {
		return backupSummary{}, err
	}
	return verifyBackupAt(directory, id, nil)
}
func restoreBackup(id, target string) (backupSummary, error) {
	dest, err := backupDestination()
	if err != nil {
		return backupSummary{}, err
	}
	target, err = absoluteRealDirectory(target)
	if err != nil {
		return backupSummary{}, err
	}
	root, err := filepath.Abs(cfg.Root)
	if err != nil {
		return backupSummary{}, err
	}
	if insideDirectory(root, target) || insideDirectory(target, root) || insideDirectory(dest, target) || insideDirectory(target, dest) {
		return backupSummary{}, errors.New("restore target must be separate from active data and backups")
	}
	// Authenticate everything before creating a recovery directory.
	if _, err = verifyBackup(id); err != nil {
		return backupSummary{}, err
	}
	if err = os.Mkdir(target, 0700); err != nil {
		return backupSummary{}, errors.New("restore requires a new, non-existing target directory")
	}
	marker := filepath.Join(target, ".warden-restore-incomplete")
	if err = os.WriteFile(marker, []byte(id), 0600); err != nil {
		return backupSummary{}, err
	}
	manifest, err := readBackupManifest(filepath.Join(dest, id), id)
	if err != nil {
		return backupSummary{}, err
	}
	for _, directory := range manifest.Directories {
		if err = os.MkdirAll(filepath.Join(target, filepath.FromSlash(directory)), 0700); err != nil {
			return backupSummary{}, err
		}
	}
	result, err := verifyBackupAt(filepath.Join(dest, id), id, func(object backupObject, reader io.Reader) error {
		path := filepath.Join(target, filepath.FromSlash(object.Path))
		if !insideDirectory(target, path) {
			return errors.New("invalid restore path")
		}
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return err
		}
		file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		written, err := io.Copy(file, reader)
		if err == nil && written != object.Size {
			err = errors.New("restored size mismatch")
		}
		if err == nil {
			err = file.Sync()
		}
		closeErr := file.Close()
		if err == nil {
			err = closeErr
		}
		return err
	})
	if err != nil {
		return result, err
	} // Leave encrypted partial recovery marked, never activate it.
	if err = os.Remove(marker); err != nil {
		return result, err
	}
	result.Status = "restored"
	return result, nil
}
func loadBackupConfig(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err = json.Unmarshal(raw, &cfg); err != nil {
		return err
	}
	key, err := decodeB64(cfg.EncryptionKey)
	if err != nil || len(key) != 32 {
		return errors.New("protected Home encryption key is required")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	aead, err = cipher.NewGCM(block)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(key)
	encryptionKeyID = hex.EncodeToString(digest[:])
	_, err = backupDestination()
	return err
}
func backupLoop(stop <-chan struct{}) {
	if cfg.BackupRoot == "" {
		return
	}
	hours := cfg.BackupIntervalHours
	if hours == 0 {
		hours = 24
	}
	if hours < 1 || hours > 720 {
		recordBackup(backupSummary{}, errors.New("invalid backup interval"))
		return
	}
	// No destructive retention. A full backup destination stops new snapshots.
	for {
		result, err := createBackup()
		recordBackup(result, err)
		if err != nil {
			log.Printf("Independent backup failed: %v", err)
		}
		timer := time.NewTimer(time.Duration(hours) * time.Hour)
		select {
		case <-stop:
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
