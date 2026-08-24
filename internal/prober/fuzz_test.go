package prober

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Lost-illusion69/recongo/models"
)

func TestNormalizeWordlistEntry(t *testing.T) {
	cases := map[string]string{
		"admin":       "/admin",
		"/admin":      "/admin",
		"  api/v1  ":  "/api/v1",
		"# comment":   "",
		"":            "",
		"http://evil": "",
		"../secret":   "",
		"foo/../bar":  "",
		"backup.zip":  "/backup.zip",
		"admin?x=1":   "/admin",
	}
	for in, want := range cases {
		if got := NormalizeWordlistEntry(in); got != want {
			t.Errorf("NormalizeWordlistEntry(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLoadWordlist(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dirs.txt")
	content := "# header\nadmin\n/admin\napi/v1\n\nsecret.php\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	words, err := LoadWordlist(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(words) != 3 {
		t.Fatalf("got %v", words)
	}
	joined := strings.Join(words, ",")
	if !strings.Contains(joined, "/admin") || !strings.Contains(joined, "/api/v1") || !strings.Contains(joined, "/secret.php") {
		t.Errorf("unexpected words: %v", words)
	}
}

func TestDefaultWordlistPath(t *testing.T) {
	p := DefaultWordlistPath()
	if !strings.Contains(filepath.ToSlash(p), "SecLists/Discovery/Web-Content/raft-medium-directories-lowercase.txt") {
		t.Errorf("unexpected default path: %s", p)
	}
}

func TestFuzzDiscoversLiveAndForbiddenPaths(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("console dashboard"))
		case "/secret.php":
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("forbidden"))
		case "/api/v1":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"ok":true}`))
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("not found"))
		}
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	hits, err := Fuzz(ctx, srv.URL, []string{"/admin", "/secret.php", "/api/v1", "/missing"}, Options{Timeout: 2 * time.Second}, 4)
	if err != nil {
		t.Fatal(err)
	}

	got := map[string]int{}
	kinds := map[string]string{}
	for _, h := range hits {
		got[h.Path] = h.StatusCode
		kinds[h.Path] = h.Kind
	}
	if got["/admin"] != 200 {
		t.Errorf("admin = %v", got)
	}
	if got["/secret.php"] != 403 {
		t.Errorf("secret.php = %v", got)
	}
	if got["/api/v1"] != 200 || kinds["/api/v1"] != "api" {
		t.Errorf("api hit = %d kind=%s", got["/api/v1"], kinds["/api/v1"])
	}
	if _, ok := got["/missing"]; ok {
		t.Errorf("404 should not be reported: %v", got)
	}
}

func TestFuzzFiltersWildcardBaseline(t *testing.T) {
	body := strings.Repeat("x", 120)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	hits, err := Fuzz(ctx, srv.URL, []string{"/admin", "/login"}, Options{Timeout: 2 * time.Second}, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 0 {
		t.Fatalf("expected wildcard filter to drop catch-all 200s, got %+v", hits)
	}
}

func TestMergeFuzzIntoEndpoints(t *testing.T) {
	out := MergeFuzzIntoEndpoints([]string{"/health"}, []models.FuzzHit{
		{Path: "/admin"},
		{Path: "/health"},
	})
	if len(out) != 2 {
		t.Fatalf("got %v", out)
	}
}

func TestFuzzEligible(t *testing.T) {
	if !FuzzEligible(200) || !FuzzEligible(403) {
		t.Fatal("200 and 403 should be eligible")
	}
	if FuzzEligible(404) || FuzzEligible(301) {
		t.Fatal("404/301 should not be eligible")
	}
}

func TestFuzzEligibleWith401(t *testing.T) {
	if !FuzzEligibleWith401(200, false) || !FuzzEligibleWith401(403, false) {
		t.Fatal("200/403 should always be eligible")
	}
	if !FuzzEligibleWith401(401, true) {
		t.Fatal("401 should be eligible when allowUnauthorized is set")
	}
	if FuzzEligibleWith401(401, false) {
		t.Fatal("401 should not be eligible by default")
	}
}

func TestExpandExtensions(t *testing.T) {
	words := ExpandExtensions([]string{"/admin", "/secret.php", "/api/v1"}, []string{"bak", "old"})
	joined := strings.Join(words, ",")
	for _, want := range []string{"/admin", "/admin.bak", "/admin.old", "/secret.php", "/api/v1", "/api/v1.bak"} {
		if !strings.Contains(joined, want) {
			t.Errorf("expansion missing %q in %v", want, words)
		}
	}
	if strings.Contains(joined, "/secret.php.bak") {
		t.Errorf("file words must not receive extension variants: %v", words)
	}
}

func TestFuzzWithConfigExtensions(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/config.bak":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("backup config"))
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("not found"))
		}
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	hits, err := FuzzWithConfig(ctx, FuzzConfig{
		BaseURL:    srv.URL,
		Words:      []string{"/config"},
		Extensions: []string{"bak"},
		Opts:       Options{Timeout: 2 * time.Second},
		Workers:    4,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].Path != "/config.bak" {
		t.Fatalf("expected /config.bak hit, got %+v", hits)
	}
}

func TestFuzzRecursiveDirectories(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin/", "/admin":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("admin area"))
		case "/admin/settings":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("settings page"))
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("not found"))
		}
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	hits, err := FuzzWithConfig(ctx, FuzzConfig{
		BaseURL: srv.URL,
		Words:   []string{"/admin/", "/settings"},
		Opts:    Options{Timeout: 2 * time.Second},
		Workers: 4,
		Depth:   2,
	})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, h := range hits {
		got[h.Path] = true
	}
	if !got["/admin/"] {
		t.Errorf("expected top-level /admin/ hit, got %+v", hits)
	}
	if !got["/admin/settings"] {
		t.Errorf("expected recursive /admin/settings hit, got %+v", hits)
	}
}

func TestFuzzRecursiveRedirectFollow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/console":
			w.Header().Set("Location", "/console/")
			w.WriteHeader(http.StatusFound)
			_, _ = w.Write([]byte("moving"))
		case "/console/":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("console home"))
		case "/console/settings":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("console settings"))
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("not found"))
		}
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	hits, err := FuzzWithConfig(ctx, FuzzConfig{
		BaseURL: srv.URL,
		Words:   []string{"/console", "/settings"},
		Opts:    Options{Timeout: 2 * time.Second},
		Workers: 4,
		Depth:   2,
	})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, h := range hits {
		got[h.Path] = true
	}
	if !got["/console/settings"] {
		t.Errorf("expected redirected /console/settings hit, got %+v", hits)
	}
}

// TestFuzzAbortsUniformBlockEarly reproduces a CDN/WAF wall that answers HTTP
// 403 for every path with varying body sizes (defeating the wildcard filter)
// and asserts the sweep stops early instead of exhausting the wordlist.
func TestFuzzAbortsUniformBlockEarly(t *testing.T) {
	var served atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		served.Add(1)
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("blocked " + r.URL.Path + strings.Repeat("z", len(r.URL.Path)%64)))
	}))
	defer srv.Close()

	words := make([]string, 0, 400)
	for i := 0; i < 400; i++ {
		words = append(words, fmt.Sprintf("/path%03d", i))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	hits, err := Fuzz(ctx, srv.URL, words, Options{Timeout: 2 * time.Second}, 8)
	var blk *BlockedError
	if !errors.As(err, &blk) {
		t.Fatalf("want BlockedError, got err=%v hits=%d", err, len(hits))
	}
	if blk.Status != http.StatusForbidden {
		t.Errorf("status = %d, want 403", blk.Status)
	}
	if n := served.Load(); n >= int64(len(words)) {
		t.Errorf("sweep did not stop early: served %d/%d requests", n, len(words))
	}
}

// TestFuzzKeepsRunningWhenStatusesVary ensures mixed-status sites are never
// mistaken for a uniform wall, even past the abort sample threshold.
func TestFuzzKeepsRunningWhenStatusesVary(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("dashboard"))
		default:
			// Varying 403 bodies: an auth wall with per-path error text.
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(strings.Repeat("x", 20+len(r.URL.Path))))
		}
	}))
	defer srv.Close()

	// Plant the live path early, mirroring how real wordlists rank common
	// directories (/admin sits near the top of SecLists).
	words := make([]string, 0, 132)
	for i := 0; i < 131; i++ {
		words = append(words, fmt.Sprintf("/miss%03d", i))
	}
	words = append(words[:5], append([]string{"/admin"}, words[5:]...)...)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	hits, err := Fuzz(ctx, srv.URL, words, Options{Timeout: 2 * time.Second}, 8)
	if err != nil {
		t.Fatalf("mixed-status sweep must not abort: %v", err)
	}
	found := map[string]int{}
	for _, h := range hits {
		found[h.Path] = h.StatusCode
	}
	if found["/admin"] != http.StatusOK {
		t.Errorf("expected /admin 200 to survive, got %+v", found)
	}
}
