package prober

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestMineEndpoints(t *testing.T) {
	body := []byte(`
	<html>
	<script src="/static/app.min.js"></script>
	<script>
	  fetch("/api/v1/users/list");
	  const gql = "/graphql";
	  const login = "/auth/oauth/callback";
	</script>
	</html>`)

	got := MineEndpoints(string(body))
	want := map[string]struct{}{
		"/api/v1/users/list":   {},
		"/graphql":             {},
		"/auth/oauth/callback": {},
	}

	if len(got) < len(want) {
		t.Fatalf("MineEndpoints() = %v, want at least %v", got, want)
	}
	for _, ep := range got {
		if _, ok := want[ep]; ok {
			delete(want, ep)
		}
	}
	if len(want) > 0 {
		t.Errorf("missing endpoints %v in %v", want, got)
	}
}

func TestMineEndpointsDedup(t *testing.T) {
	body := []byte(`"/api/v2/foo" "/api/v2/foo" "/graphql"`)
	got := MineEndpoints(string(body))
	if len(got) != 2 {
		t.Errorf("expected 2 unique endpoints, got %v", got)
	}
}

func TestParseHeaders(t *testing.T) {
	h, err := ParseHeaders("Authorization: Bearer xyz, X-Forwarded-For: 127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if h["Authorization"] != "Bearer xyz" {
		t.Errorf("Authorization = %q", h["Authorization"])
	}
	if h["X-Forwarded-For"] != "127.0.0.1" {
		t.Errorf("X-Forwarded-For = %q", h["X-Forwarded-For"])
	}
}

func TestParseHeadersInvalid(t *testing.T) {
	_, err := ParseHeaders("badheader")
	if err == nil {
		t.Fatal("expected error for invalid header")
	}
}

func TestPickUserAgentRotation(t *testing.T) {
	seen := make(map[string]struct{})
	for i := 0; i < 50; i++ {
		seen[pickUserAgent(true)] = struct{}{}
	}
	if len(seen) < 2 {
		t.Errorf("expected multiple user agents, got %d", len(seen))
	}
	if pickUserAgent(false) != defaultUserAgent {
		t.Error("random-agent disabled should use default UA")
	}
}

func TestApplyHeadersCustom(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	opts := Options{
		RandomAgent: false,
		Headers:     map[string]string{"X-Test": "1"},
	}
	applyHeaders(req, opts)
	if req.Header.Get("X-Test") != "1" {
		t.Errorf("X-Test = %q", req.Header.Get("X-Test"))
	}
	if !strings.Contains(req.Header.Get("User-Agent"), "ReconGo") {
		t.Errorf("UA = %q", req.Header.Get("User-Agent"))
	}
}

func TestProbeCustomHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer testtoken" {
			http.Error(w, "missing auth", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `<html><script>"/api/v1/health"</script></html>`)
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	result, err := Probe(host, Options{
		Timeout:     3 * time.Second,
		RandomAgent: false,
		Headers:     map[string]string{"Authorization": "Bearer testtoken"},
	})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(result.Endpoints) == 0 {
		t.Errorf("expected mined endpoints, got none")
	}
}
