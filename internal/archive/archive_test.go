package archive

import (
	"net/url"
	"testing"
)

func TestIsInScope(t *testing.T) {
	cases := []struct {
		host, domain string
		want         bool
	}{
		{"api.example.com", "example.com", true},
		{"example.com", "example.com", true},
		{"evil.com", "example.com", false},
	}
	for _, tc := range cases {
		if got := isInScope(tc.host, tc.domain); got != tc.want {
			t.Errorf("isInScope(%q,%q)=%v want %v", tc.host, tc.domain, got, tc.want)
		}
	}
}

func TestExtractQueryParams(t *testing.T) {
	v := url.Values{}
	v.Set("token", "abc")
	v.Set("debug", "1")
	params := extractQueryParams(v)
	if len(params) != 2 {
		t.Fatalf("got %d params", len(params))
	}
}

func TestSortedKeys(t *testing.T) {
	m := map[string]struct{}{"b": {}, "a": {}}
	got := sortedKeys(m)
	if len(got) != 2 || got[0] != "a" {
		t.Errorf("sortedKeys() = %v", got)
	}
}

func TestFilterForHostEmpty(t *testing.T) {
	urls, params := FilterForHost(nil, "example.com")
	if urls == nil || params == nil {
		t.Error("expected empty slices")
	}
}

func TestFindingsStructure(t *testing.T) {
	f := &Findings{
		Subdomains:       []string{"a.example.com"},
		HistoricalURLs:   []string{"/api/v1"},
		DiscoveredParams: []string{"token"},
	}
	urls, params := FilterForHost(f, "a.example.com")
	if len(urls) != 1 || len(params) != 1 {
		t.Errorf("FilterForHost() urls=%v params=%v", urls, params)
	}
}
