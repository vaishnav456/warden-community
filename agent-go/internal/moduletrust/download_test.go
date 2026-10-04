package moduletrust

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestStageVerifiedBlob(t *testing.T) {
	g, c, key, blob := fixture(t)
	a, err := Verify(signed(g, key), c)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("Authorization") != "fixture-only" {
			t.Fatal("missing endpoint authentication")
		}
		return &http.Response{StatusCode: 200, ContentLength: int64(len(blob)), Body: io.NopCloser(bytes.NewReader(blob)), Header: make(http.Header)}, nil
	})}
	path, err := a.stage(context.Background(), directory, func(r *http.Request) error { r.Header.Set("Authorization", "fixture-only"); return nil }, client, func() time.Time { return c.Now })
	if err != nil {
		t.Fatal(err)
	}
	stored, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(stored, blob) {
		t.Fatal("verified blob not staged", err)
	}
}

func TestStageFailuresLeaveNoArtifact(t *testing.T) {
	for _, name := range []string{"tampered", "short", "oversized", "redirect", "revoked", "server error", "encoded", "length", "expired", "expired during transfer", "cancelled", "auth error", "auth changes URL", "network error"} {
		t.Run(name, func(t *testing.T) {
			g, c, key, blob := fixture(t)
			a, err := Verify(signed(g, key), c)
			if err != nil {
				t.Fatal(err)
			}
			directory := t.TempDir()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			clock := c.Now
			if name == "expired" {
				clock = time.Unix(g.ExpiresAt, 0)
			}
			client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				status, length := 200, int64(-1)
				header := make(http.Header)
				switch name {
				case "tampered":
					blob = bytes.Repeat([]byte{'x'}, len(blob))
				case "short":
					blob = blob[:len(blob)-1]
				case "oversized":
					blob = append(blob, 'x')
				case "redirect":
					status = 302
					header.Set("Location", "https://attacker.example/")
				case "revoked":
					status = 403
				case "server error":
					status = 500
				case "encoded":
					header.Set("Content-Encoding", "gzip")
				case "length":
					length = 1
				case "expired during transfer":
					clock = time.Unix(g.ExpiresAt, 0)
				case "cancelled":
					cancel()
				case "network error":
					return nil, errors.New("fixture")
				}
				return &http.Response{StatusCode: status, ContentLength: length, Header: header, Body: io.NopCloser(bytes.NewReader(blob)), Request: r}, nil
			})}
			path, err := a.stage(ctx, directory, func(r *http.Request) error {
				if name == "auth error" {
					return errors.New("fixture")
				}
				if name == "auth changes URL" {
					r.URL.Host = "attacker.example"
				}
				return nil
			}, client, func() time.Time { return clock })
			if err == nil || path != "" {
				t.Fatal("unsafe download accepted", path, err)
			}
			files, err := os.ReadDir(directory)
			if err != nil || len(files) != 0 {
				t.Fatal("failed download left files", files, err)
			}
		})
	}
}

func TestStageRequiresAuthentication(t *testing.T) {
	g, c, key, _ := fixture(t)
	a, _ := Verify(signed(g, key), c)
	if _, err := a.stage(context.Background(), t.TempDir(), nil, nil, func() time.Time { return c.Now }); err == nil {
		t.Fatal("unauthenticated download accepted")
	}
	var absent *Approved
	if _, err := absent.stage(context.Background(), t.TempDir(), nil, nil, time.Now); err == nil {
		t.Fatal("missing grant accepted")
	}
}

func TestPinnedTransportCannotFollowRedirects(t *testing.T) {
	g, c, key, _ := fixture(t)
	a, err := Verify(signed(g, key), c)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { t.Fatal("caller redirect policy used"); return nil }, Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 302, ContentLength: 0, Body: io.NopCloser(bytes.NewReader(nil)), Header: http.Header{"Location": []string{"https://attacker.example/"}}, Request: r}, nil
	})}
	if _, err = a.StageWithClient(context.Background(), t.TempDir(), func(*http.Request) error { return nil }, client, func() time.Time { return c.Now }); err == nil {
		t.Fatal("redirect accepted")
	}
	if calls != 1 {
		t.Fatal("authentication sent to redirected target")
	}
}
