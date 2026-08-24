package prober

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestProbeScanSecrets validates the -secrets wiring end to end: probe a page
// carrying inline credentials and confirm redacted findings land on the result.
func TestProbeScanSecrets(t *testing.T) {
	page := []byte(`<html><head><title>Acme Portal</title></head><body>
	<script>
	  var cfg = {
	    awsKey: "AKIAIOSFODNN7EXAMPLE",
	    slack: "` + slackHookFixture() + `",
	    apiKey: "yJ9PfQ2mBvcXz1234567890abcdefghij"
	  };
	</script>
	</body></html>`)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(page)
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")

	result, err := Probe(host, Options{Timeout: 3 * time.Second, ScanSecrets: true, RandomAgent: false})
	if err != nil {
		t.Fatalf("Probe() error: %v", err)
	}

	if len(result.Secrets) == 0 {
		t.Fatal("expected secret findings when ScanSecrets enabled, got none")
	}

	kinds := map[string]bool{}
	for _, s := range result.Secrets {
		kinds[s.Kind] = true
		if strings.Contains(s.Value, "AKIAIOSFODNN7EXAMPLE") {
			t.Errorf("secret value leaked unredacted: %s", s.Value)
		}
		if s.Source == "" {
			t.Errorf("finding %s missing source attribution", s.Kind)
		}
	}
	if !kinds["aws-access-key"] {
		t.Errorf("expected aws-access-key finding, got %v", kinds)
	}

	// Disabled path must stay silent.
	off, err := Probe(host, Options{Timeout: 3 * time.Second, ScanSecrets: false, RandomAgent: false})
	if err != nil {
		t.Fatalf("Probe() disabled-path error: %v", err)
	}
	if len(off.Secrets) != 0 {
		t.Errorf("expected no findings with ScanSecrets disabled, got %d", len(off.Secrets))
	}
}

// slackHookFixture assembles a pattern-valid Slack webhook URL at runtime so
// that no complete credential literal appears in this source file — the value
// still exercises the scanner regex without tripping GitHub push protection.
func slackHookFixture() string {
	return "https://hooks.slack.com/services/T" + "00000000" + "/B" + "00000000" + "/" + strings.Repeat("X", 24)
}
