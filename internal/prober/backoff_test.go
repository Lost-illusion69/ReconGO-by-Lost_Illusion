package prober

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestShouldRetryStatus(t *testing.T) {
	if !shouldRetryStatus(429) || !shouldRetryStatus(503) {
		t.Error("expected retry statuses")
	}
	if shouldRetryStatus(200) {
		t.Error("unexpected retry for 200")
	}
}

func TestAdaptiveBackoffRetry(t *testing.T) {
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 3 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><title>OK</title></html>`))
	}))
	defer srv.Close()

	host := srv.Listener.Addr().String()
	resetBackoff(host)

	result, err := Probe(host, Options{
		Timeout:     5 * time.Second,
		RandomAgent: false,
		Delay:       0,
	})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if result.StatusCode != http.StatusOK {
		t.Errorf("status = %d, attempts = %d", result.StatusCode, attempts)
	}
	if attempts < 3 {
		t.Errorf("expected retries, got %d attempts", attempts)
	}
}

func TestDiagnosticHeadersInjected(t *testing.T) {
	var gotFor, gotReal, gotDebug string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotFor = r.Header.Get("X-Forwarded-For")
		gotReal = r.Header.Get("X-Real-IP")
		gotDebug = r.Header.Get("X-Debug")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	host := srv.Listener.Addr().String()
	_, err := Probe(host, Options{Timeout: 3 * time.Second, RandomAgent: false})
	if err != nil {
		t.Fatal(err)
	}
	if gotFor != "127.0.0.1" || gotReal != "127.0.0.1" || gotDebug != "1" {
		t.Errorf("headers = %q %q %q", gotFor, gotReal, gotDebug)
	}
}
