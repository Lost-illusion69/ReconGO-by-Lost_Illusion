package engine

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Lost-illusion69/recongo/pkg/dns"
)

func TestProbePoolRun(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "pool-test")
		fmt.Fprint(w, `<title>Pool Title</title>`)
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")

	in := make(chan dns.LookupResult, 2)
	in <- dns.LookupResult{Host: host, IPs: []string{"127.0.0.1"}}
	in <- dns.LookupResult{Host: "does-not-resolve.invalid", Err: fmt.Errorf("no such host")}
	close(in)

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	pool := NewProbePool(ProbeConfig{
		Workers: 4,
		Timeout: 3 * time.Second,
	}, log)

	out := pool.Run(context.Background(), in)

	var got int
	for a := range out {
		got++
		if a.Host != host {
			t.Errorf("Host = %q, want %q", a.Host, host)
		}
		if a.Title != "Pool Title" {
			t.Errorf("Title = %q, want %q", a.Title, "Pool Title")
		}
		if len(a.IPs) != 1 || a.IPs[0] != "127.0.0.1" {
			t.Errorf("IPs = %v, want [127.0.0.1]", a.IPs)
		}
	}
	if got != 1 {
		t.Fatalf("expected 1 probed asset, got %d", got)
	}
}
