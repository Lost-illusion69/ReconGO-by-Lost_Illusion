package prober

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Lost-illusion69/recongo/internal/mmh3"
)

func TestProbeBodyMMH3(t *testing.T) {
	body := []byte(`<html><head><title>Hash Me</title></head><body>payload</body></html>`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "mmh3-test")
		fmt.Fprint(w, string(body))
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	result, err := Probe(host, Options{Timeout: 3 * time.Second})
	if err != nil {
		t.Fatalf("Probe() error: %v", err)
	}
	if result.BodyMMH3 != mmh3.Hash(body) {
		t.Errorf("BodyMMH3 = %d, want %d", result.BodyMMH3, mmh3.Hash(body))
	}
}

func TestProbeFaviconMMH3(t *testing.T) {
	icon := []byte{0x00, 0x01, 0x02, 0x03, 0x04}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			fmt.Fprint(w, `<html><head><link rel="icon" href="/favicon.ico"></head></html>`)
		case "/favicon.ico":
			w.Write(icon)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	result, err := Probe(host, Options{Timeout: 3 * time.Second})
	if err != nil {
		t.Fatalf("Probe() error: %v", err)
	}
	want := mmh3.FaviconHash(icon)
	if result.FaviconMMH3 != want {
		t.Errorf("FaviconMMH3 = %d, want %d", result.FaviconMMH3, want)
	}
}

func TestProbeFaviconFallbackPath(t *testing.T) {
	icon := []byte("fallback-icon")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			fmt.Fprint(w, `<html><body>no link tag</body></html>`)
		case "/favicon.ico":
			w.Write(icon)
		}
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	result, err := Probe(host, Options{Timeout: 3 * time.Second})
	if err != nil {
		t.Fatalf("Probe() error: %v", err)
	}
	if result.FaviconMMH3 != mmh3.FaviconHash(icon) {
		t.Errorf("FaviconMMH3 = %d, want fallback hash", result.FaviconMMH3)
	}
}
