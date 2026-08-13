package archive

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
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

func TestNewClientDefaults(t *testing.T) {
	c := NewClient()
	if c.HTTP == nil || c.Limit != defaultLimit {
		t.Errorf("NewClient() = %+v", c)
	}
}

func TestQueryEmptyDomain(t *testing.T) {
	_, err := Query(context.Background(), "", NewClient())
	if err == nil || !strings.Contains(err.Error(), "empty domain") {
		t.Errorf("Query() err = %v", err)
	}
}

func TestQueryIntegration(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "cdx/search/cdx"):
			_ = json.NewEncoder(w).Encode([][]string{
				{"original"},
				{"https://api.example.com/api/v1/users?debug=1"},
			})
		case strings.Contains(r.URL.Path, "passive_dns"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"passive_dns": []map[string]string{{"hostname": "mail.example.com"}},
			})
		case strings.Contains(r.URL.Path, "url_list"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"url_list": []map[string]string{{"url": "https://www.example.com/search?q=test"}},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	client := &Client{
		HTTP: &http.Client{
			Transport: newRewriteTransport(srv.URL),
			Timeout:   5 * time.Second,
		},
		Limit: 100,
	}

	findings, err := Query(context.Background(), "example.com", client)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings.Subdomains) == 0 {
		t.Errorf("expected subdomains, got %v", findings)
	}
	if len(findings.HistoricalURLs) == 0 {
		t.Errorf("expected URLs, got %v", findings.HistoricalURLs)
	}
	if len(findings.DiscoveredParams) == 0 {
		t.Errorf("expected params, got %v", findings.DiscoveredParams)
	}
}

func newRewriteTransport(base string) http.RoundTripper {
	base = strings.TrimPrefix(base, "http://")
	return roundTripFunc(func(req *http.Request) (*http.Response, error) {
		clone := req.Clone(req.Context())
		clone.URL.Scheme = "http"
		clone.URL.Host = base
		return http.DefaultTransport.RoundTrip(clone)
	})
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestAddURLParsing(t *testing.T) {
	subSeen := make(map[string]struct{})
	urlSeen := make(map[string]struct{})
	paramSeen := make(map[string]struct{})

	addSub := func(host string) {
		if isInScope(host, "example.com") {
			subSeen[host] = struct{}{}
		}
	}
	addURL := func(raw string) {
		u, err := url.Parse(raw)
		if err != nil {
			return
		}
		path := u.Path
		if u.RawQuery != "" {
			path += "?" + u.RawQuery
			for p := range extractQueryParams(u.Query()) {
				paramSeen[p] = struct{}{}
			}
		}
		urlSeen[path] = struct{}{}
		if u.Hostname() != "" {
			addSub(u.Hostname())
		}
	}

	addURL("https://api.example.com/v1/data?token=abc&session=xyz")
	if len(subSeen) != 1 {
		t.Errorf("subdomains = %v", subSeen)
	}
	if len(paramSeen) != 2 {
		t.Errorf("params = %v", paramSeen)
	}
	if len(urlSeen) != 1 {
		t.Errorf("urls = %v", urlSeen)
	}
}
