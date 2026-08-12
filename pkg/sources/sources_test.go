package sources

import (
	"testing"
)

// ---------------------------------------------------------------------------
// CrtSh.deduplicate tests
// ---------------------------------------------------------------------------

func TestCrtShDeduplicate(t *testing.T) {
	c := NewCrtSh()

	entries := []crtShEntry{
		{NameValue: "api.example.com"},
		{NameValue: "api.example.com"},                  // exact duplicate → must be dropped
		{NameValue: "*.api.example.com"},                // wildcard → strip to api.example.com, dup
		{NameValue: "dev.example.com\nstg.example.com"}, // multi-value newline
		{NameValue: "UPPER.example.com"},                // case → normalise to lower
		{NameValue: "unrelated.com"},                    // different domain → must be dropped
		{NameValue: "example.com"},                      // exact match of target → keep
	}

	results := c.deduplicate(entries, "example.com")

	got := make(map[string]int)
	for _, r := range results {
		got[r.Value]++
		if r.Source != crtShName {
			t.Errorf("result %q has wrong source %q", r.Value, r.Source)
		}
	}

	mustExist := []string{"api.example.com", "dev.example.com", "stg.example.com", "upper.example.com", "example.com"}
	for _, want := range mustExist {
		if got[want] != 1 {
			t.Errorf("expected %q exactly once, got %d times", want, got[want])
		}
	}

	if _, found := got["unrelated.com"]; found {
		t.Error("unrelated.com should have been filtered out")
	}

	// Total unique entries after dedup
	if len(results) != len(mustExist) {
		t.Errorf("expected %d unique results, got %d: %v", len(mustExist), len(results), results)
	}
}

// ---------------------------------------------------------------------------
// AlienVault.deduplicate tests
// ---------------------------------------------------------------------------

func TestAlienVaultDeduplicate(t *testing.T) {
	a := NewAlienVault()

	entries := []otxPassiveDNSEntry{
		{Hostname: "mail.example.com"},
		{Hostname: "mail.example.com"}, // duplicate → drop
		{Hostname: "MAIL.example.com"}, // case variant → normalise and drop
		{Hostname: "vpn.example.com"},
		{Hostname: "notexample.net"}, // different TLD → drop
		{Hostname: ""},               // empty → drop
	}

	results := a.deduplicate(entries, "example.com")

	got := make(map[string]int)
	for _, r := range results {
		got[r.Value]++
		if r.Source != alienVaultName {
			t.Errorf("result %q has wrong source %q", r.Value, r.Source)
		}
	}

	mustExist := []string{"mail.example.com", "vpn.example.com"}
	for _, want := range mustExist {
		if got[want] != 1 {
			t.Errorf("expected %q exactly once, got %d times", want, got[want])
		}
	}

	if len(results) != len(mustExist) {
		t.Errorf("expected %d unique results, got %d", len(mustExist), len(results))
	}
}
