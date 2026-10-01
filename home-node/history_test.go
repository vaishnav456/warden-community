package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
)

func TestHistoryOptInEncryptedAndQuotaAccounted(t *testing.T) {
	configureTestCrypto(t)
	cfg.Root = t.TempDir()
	rel := "homes/alice/Documents/file.txt"
	g := grant{Prefix: "homes/alice", MaxFileBytes: 1024, HistoryDays: 0}
	if status, err := storeAuthorizedFile(rel, bytes.NewBufferString("first"), 123, g); err != nil || status != 204 {
		t.Fatal(status, err)
	}
	if status, err := storeAuthorizedFile(rel, bytes.NewBufferString("second"), 124, g); err != nil || status != 204 {
		t.Fatal(status, err)
	}
	versions, err := listHomeVersions(rel)
	if err != nil || len(versions) != 0 {
		t.Fatal("history must default off", versions, err)
	}
	g.HistoryDays = 30
	if status, err := storeAuthorizedFile(rel, bytes.NewBufferString("third"), 125, g); err != nil || status != 204 {
		t.Fatal(status, err)
	}
	versions, err = listHomeVersions(rel)
	if err != nil || len(versions) != 1 {
		t.Fatal(versions, err)
	}
	blob, record, err := historyPaths(rel, versions[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(blob)
	descriptor, _ := os.ReadFile(record)
	if bytes.Contains(raw, []byte("second")) || bytes.Contains(descriptor, []byte(versions[0].SHA256)) {
		t.Fatal("history plaintext leaked")
	}
	var plain bytes.Buffer
	if err := decryptStreamForPath(&plain, bytes.NewReader(raw), rel); err != nil || plain.String() != "second" {
		t.Fatal(plain.String(), err)
	}
	if _, err := readHomeVersion("homes/bob/Documents/file.txt", versions[0].ID); err == nil {
		t.Fatal("history moved across owners")
	}
	usage := prefixUsage(g.Prefix)
	if err != nil || usage <= 5 {
		t.Fatal("history not counted", usage, err)
	}
	g.QuotaBytes = usage
	if status, err := storeAuthorizedFile(rel, bytes.NewBufferString("large"), 126, g); err == nil || status != 507 {
		t.Fatal("history bypassed quota", status, err)
	}
	data, _, _ := pathsFor(rel)
	raw, _ = os.ReadFile(data)
	plain.Reset()
	if err := decryptStreamForPath(&plain, bytes.NewReader(raw), rel); err != nil || plain.String() != "third" {
		t.Fatal("quota rejection changed original", plain.String(), err)
	}
	descriptor[len(descriptor)-1] ^= 1
	os.WriteFile(record, descriptor, 0600)
	if _, err := listHomeVersions(rel); err == nil {
		t.Fatal("tampered descriptor accepted")
	}
}

func TestHistoryRestoreRequiresCurrentVersionAndPreservesOtherFiles(t *testing.T) {
	private := configureTestCrypto(t)
	cfg.Root = t.TempDir()
	rel := "homes/alice/Documents/file.txt"
	g := grant{Prefix: "homes/alice", MaxFileBytes: 1024, HistoryDays: 7}
	for i, content := range []string{"before", "after"} {
		if status, err := storeAuthorizedFile(rel, bytes.NewBufferString(content), int64(123+i), g); err != nil || status != 204 {
			t.Fatal(status, err)
		}
	}
	versions, err := listHomeVersions(rel)
	if err != nil || len(versions) != 1 {
		t.Fatal(versions, err)
	}
	token := testGrant(t, private, g.Prefix)
	path := "/v1/history?path=" + url.QueryEscape(rel) + "&version=" + versions[0].ID
	restore := func(expected, auth string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, path, nil)
		r.Header.Set("Authorization", "Bearer "+auth)
		r.Header.Set("X-Warden-Expected-Version", expected)
		w := httptest.NewRecorder()
		handleHistory(w, r)
		return w
	}
	if w := restore("stale", token); w.Code != 412 {
		t.Fatal("stale restore accepted", w.Code, w.Body.String())
	}
	current, err := storedVersion(rel)
	if err != nil {
		t.Fatal(err)
	}
	if w := restore(current, testGrant(t, private, "homes/bob")); w.Code != 401 {
		t.Fatal("cross-owner restore accepted", w.Code)
	}
	if w := restore(current, token); w.Code != 204 || w.Header().Get("X-Warden-SHA256") != versions[0].SHA256 {
		t.Fatal("restore failed", w.Code, w.Body.String())
	}
	data, _, _ := pathsFor(rel)
	raw, _ := os.ReadFile(data)
	var plain bytes.Buffer
	if err := decryptStreamForPath(&plain, bytes.NewReader(raw), rel); err != nil || plain.String() != "before" {
		t.Fatal("wrong restored plaintext", plain.String(), err)
	}
	if w := restore(current, token); w.Code != 412 {
		t.Fatal("repeated stale restore accepted", w.Code)
	}
}

func TestHistoryDeletionPreservesEncryptedVersionOnlyWhenEnabled(t *testing.T) {
	configureTestCrypto(t)
	cfg.Root = t.TempDir()
	rel := "homes/alice/Documents/file.txt"
	if err := writeFile(rel, bytes.NewBufferString("hello"), 123, 1024); err != nil {
		t.Fatal(err)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256([]byte("hello")))
	g := grant{Prefix: "homes/alice", MaxFileBytes: 1024, HistoryDays: 7}
	if status, err := confirmHomeDeletion(rel, digest, g); err != nil || status != 204 {
		t.Fatal(status, err)
	}
	versions, err := listHomeVersions(rel)
	if err != nil || len(versions) != 1 || !versions[0].Deleted {
		t.Fatal(versions, err)
	}
	data, meta, _ := pathsFor(rel)
	for _, path := range []string{data, meta} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("active deleted data remains", path, err)
		}
	}
	if status, err := confirmHomeDeletion(rel, digest, g); err != nil || status != 204 {
		t.Fatal(status, err)
	}
	versions, err = listHomeVersions(rel)
	if err != nil || len(versions) != 1 {
		t.Fatal("deletion retry duplicated history", versions, err)
	}
}

func TestHistoryDoesNotHideOrWriteIntoSimilarlyNamedUserFolders(t *testing.T) {
	configureTestCrypto(t)
	cfg.Root = t.TempDir()
	prefix := "homes/alice"
	rel := prefix + "/Documents/foo.whome.history/file.txt"
	if err := writeFile(rel, bytes.NewBufferString("user content"), 123, 1024); err != nil {
		t.Fatal(err)
	}
	entries, err := listStoredFiles(prefix)
	if err != nil || len(entries) != 1 || entries[0].Path != rel {
		t.Fatal("user folder hidden", entries, err)
	}
	original := prefix + "/Documents/foo"
	if err := writeFile(original, bytes.NewBufferString("active"), 123, 1024); err != nil {
		t.Fatal(err)
	}
	if err := archiveHomeVersion(original, 30, false); err == nil {
		t.Fatal("archive wrote inside existing user folder")
	}
	entries, err = listStoredFiles(prefix)
	if err != nil || len(entries) != 2 {
		t.Fatal("collision altered stored files", entries, err)
	}
}
