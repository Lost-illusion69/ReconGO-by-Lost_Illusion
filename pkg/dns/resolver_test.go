package dns

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestLookupResultResolved(t *testing.T) {
	cases := []struct {
		name string
		r    LookupResult
		want bool
	}{
		{"ok", LookupResult{Host: "a", IPs: []string{"1.2.3.4"}}, true},
		{"error", LookupResult{Host: "a", Err: context.DeadlineExceeded}, false},
		{"empty", LookupResult{Host: "a", IPs: nil}, false},
	}
	for _, tc := range cases {
		if got := tc.r.Resolved(); got != tc.want {
			t.Errorf("%s: Resolved() = %v want %v", tc.name, got, tc.want)
		}
	}
}

func TestConfigWithDefaults(t *testing.T) {
	c := (&Config{}).withDefaults()
	if c.Workers != 100 {
		t.Errorf("workers = %d", c.Workers)
	}
	if c.Timeout != 5*time.Second {
		t.Errorf("timeout = %v", c.Timeout)
	}
}

func TestNewResolverBadNameserver(t *testing.T) {
	_, err := NewResolver(Config{Nameservers: []string{"not-a-valid-addr"}})
	if err == nil {
		t.Fatal("expected error for malformed nameserver")
	}
	if !strings.Contains(err.Error(), "bad nameserver") {
		t.Errorf("error = %v", err)
	}
}

func TestNewResolverDefaults(t *testing.T) {
	r, err := NewResolver(Config{})
	if err != nil {
		t.Fatal(err)
	}
	if r.cfg.Workers != 100 {
		t.Errorf("workers = %d", r.cfg.Workers)
	}
}

func TestResolveAllCancels(t *testing.T) {
	r, err := NewResolver(Config{Workers: 2, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	hosts := make(chan string, 1)
	hosts <- "example.com"
	close(hosts)

	out := r.ResolveAll(ctx, hosts)
	for range out {
	}
}
