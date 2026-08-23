package prober

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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
