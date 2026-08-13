package prober

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Title extraction
// ---------------------------------------------------------------------------

func TestExtractTitle(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "simple",
			body: "<html><head><title>Hello World</title></head></html>",
			want: "Hello World",
		},
		{
			name: "case insensitive",
			body: "<HTML><HEAD><TITLE>Mixed Case</TITLE></HEAD></HTML>",
			want: "Mixed Case",
		},
		{
			name: "with attributes",
			body: `<title lang="en">Attr Title</title>`,
			want: "Attr Title",
		},
		{
			name: "multiline whitespace",
			body: "<title>\n  Spaced\n  Title  \n</title>",
			want: "Spaced Title",
		},
		{
			name: "absent",
			body: "<html><body>no title here</body></html>",
			want: "",
		},
		{
			name: "empty title",
			body: "<title></title>",
			want: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ExtractTitle([]byte(tc.body))
			if got != tc.want {
				t.Errorf("extractTitle() = %q, want %q", got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Probe against httptest
// ---------------------------------------------------------------------------

func TestProbeStatusAndTitle(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "test-server/1.0")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `<!doctype html><html><head><title>Probe OK</title></head><body>hi</body></html>`)
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")

	result, err := Probe(host, Options{Timeout: 3 * time.Second})
	if err != nil {
		t.Fatalf("Probe() unexpected error: %v", err)
	}

	if result.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", result.StatusCode, http.StatusOK)
	}
	if result.Title != "Probe OK" {
		t.Errorf("Title = %q, want %q", result.Title, "Probe OK")
	}
	if result.Server != "test-server/1.0" {
		t.Errorf("Server = %q, want %q", result.Server, "test-server/1.0")
	}
	if result.Host != host {
		t.Errorf("Host = %q, want %q", result.Host, host)
	}
	if !strings.HasPrefix(result.URL, "http://") && !strings.HasPrefix(result.URL, "https://") {
		t.Errorf("URL = %q, want http(s) scheme", result.URL)
	}
	if result.ContentLength <= 0 {
		t.Errorf("ContentLength = %d, want > 0", result.ContentLength)
	}
	if result.ResponseTime <= 0 {
		t.Errorf("ResponseTime = %v, want > 0", result.ResponseTime)
	}
}

func TestProbeForbiddenStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `<title>Denied</title>`)
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")

	result, err := Probe(host, Options{Timeout: 3 * time.Second})
	if err != nil {
		t.Fatalf("Probe() unexpected error: %v", err)
	}
	if result.StatusCode != http.StatusForbidden {
		t.Errorf("StatusCode = %d, want %d", result.StatusCode, http.StatusForbidden)
	}
	if result.Title != "Denied" {
		t.Errorf("Title = %q, want %q", result.Title, "Denied")
	}
}

func TestProbeTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")

	_, err := Probe(host, Options{Timeout: 100 * time.Millisecond})
	if err == nil {
		t.Fatal("Probe() expected timeout error, got nil")
	}
}

func TestProbeEmptyHost(t *testing.T) {
	_, err := Probe("", Options{Timeout: time.Second})
	if err == nil {
		t.Fatal("Probe(\"\") expected error, got nil")
	}
}

func TestProbeBodyLimit(t *testing.T) {
	// Serve more than 1 MiB; ContentLength on the result must be capped.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		chunk := strings.Repeat("A", 64*1024)
		for i := 0; i < 20; i++ { // 20 * 64 KiB = 1.25 MiB
			fmt.Fprint(w, chunk)
		}
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")

	result, err := Probe(host, Options{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("Probe() unexpected error: %v", err)
	}
	if result.ContentLength > maxBodyBytes {
		t.Errorf("ContentLength = %d, want ≤ %d", result.ContentLength, maxBodyBytes)
	}
	if result.ContentLength != maxBodyBytes {
		t.Errorf("ContentLength = %d, want exactly %d (LimitReader cap)", result.ContentLength, maxBodyBytes)
	}
}

func TestProbeHTTPSServer(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "tls-test")
		fmt.Fprint(w, `<title>Secure</title>`)
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "https://")

	result, err := Probe(host, Options{Timeout: 3 * time.Second})
	if err != nil {
		t.Fatalf("Probe() unexpected error: %v", err)
	}
	if result.Title != "Secure" {
		t.Errorf("Title = %q, want %q", result.Title, "Secure")
	}
	if !strings.HasPrefix(result.URL, "https://") {
		t.Errorf("URL = %q, want https:// prefix (HTTPS preferred)", result.URL)
	}
	if result.Server != "tls-test" {
		t.Errorf("Server = %q, want %q", result.Server, "tls-test")
	}
}
