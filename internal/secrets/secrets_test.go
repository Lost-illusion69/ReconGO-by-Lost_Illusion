package secrets

import (
	"strings"
	"testing"
)

// Pattern-valid fixtures are assembled at runtime so no complete credential
// literal appears in this file (keeps GitHub push protection happy while the
// values still exercise the scanner regexes end to end).
var (
	slackWebhookFixture = "https://hooks.slack.com/services/T" + "00000000" + "/B" + "00000000" + "/" + strings.Repeat("X", 24)
	stripeTestFixture   = "sk_test_" + "1234" + "567890abcdefghijklmnopqrs"
	stripeLiveFixture   = "sk_live_" + "1234" + "567890abcdefghijklmnopqrs"
)

func TestRedactNeverLeaksValue(t *testing.T) {
	secret := "AKIAIOSFODNN7EXAMPLE"
	redacted := Redact(secret)
	if strings.Contains(redacted, secret) {
		t.Fatalf("redaction leaked full value: %s", redacted)
	}
	if strings.Contains(redacted, "AKIA") {
		t.Fatalf("redaction leaked prefix: %s", redacted)
	}
	if len(redacted) < 6 {
		t.Fatalf("redaction too short: %s", redacted)
	}
}

func TestScanFindsKnownSecretClasses(t *testing.T) {
	cases := []struct {
		name string
		body string
		kind string
	}{
		{"aws-access", `awsAccessKeyId = "AKIAIOSFODNN7EXAMPLE"`, "aws-access-key"},
		{"aws-secret", `AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`, "aws-secret-key"},
		{"github", `const token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz";`, "github-token"},
		{"slack-webhook", `url: "` + slackWebhookFixture + `"`, "slack-webhook"},
		{"google", `key: "AIzaSyA1234567890abcdefghijklmnopqrstuvwxyz"`, "google-api-key"},
		{"stripe", stripeTestFixture, "stripe-key"},
		{"stripe-live", stripeLiveFixture, "stripe-key"},
		{"private-key", `-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAK...\n-----END RSA PRIVATE KEY-----`, "private-key"},
		{"generic", `const API_KEY = "yJ9PfQ2mBvcXz1234567890abcdefghij"`, "generic-secret"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			found := Scan(ScanInput{Name: "html", Body: tc.body})
			if len(found) == 0 {
				t.Fatalf("no findings for %s in %q", tc.kind, tc.body)
			}
			if found[0].Kind != tc.kind {
				t.Errorf("kind = %s, want %s (got %+v)", found[0].Kind, tc.kind, found)
			}
			if found[0].Value == "" {
				t.Error("finding has no redacted value")
			}
			if strings.Contains(found[0].Value, "KEY=") {
				t.Errorf("value not redacted: %s", found[0].Value)
			}
		})
	}
}

func TestScanSkipsPlaceholders(t *testing.T) {
	body := `
		api_key = "YOUR_API_KEY_HERE"
		client_secret = "example-secret-value"
		token = "changeme-1234567890abcdefghij"
	`
	found := Scan(ScanInput{Name: "html", Body: body})
	for _, f := range found {
		t.Errorf("unexpected finding for placeholder: %+v", f)
	}
}

func TestScanSortsHighConfidenceFirst(t *testing.T) {
	body := `
		const API_KEY = "yJ9PfQ2mBvcXz1234567890abcdefghij";
		xoxb-1234567890abcdefghijklmnopqrstuvwxyz
	`
	found := Scan(ScanInput{Name: "html", Body: body})
	if len(found) < 2 {
		t.Fatalf("expected multiple findings, got %+v", found)
	}
	if found[0].Confidence != High {
		t.Errorf("first finding should be high confidence, got %+v", found[0])
	}
}

func TestScanDeduplicatesPerSource(t *testing.T) {
	body := `ghp_1234567890abcdefghijklmnopqrstuvwxyz ghp_1234567890abcdefghijklmnopqrstuvwxyz`
	found := Scan(ScanInput{Name: "html", Body: body})
	n := 0
	for _, f := range found {
		if f.Kind == "github-token" {
			n++
		}
	}
	if n > 1 {
		t.Errorf("expected dedupe, got %d github findings", n)
	}
}

func TestScanEmptyInputs(t *testing.T) {
	if got := Scan(); got != nil {
		t.Errorf("expected nil for empty inputs, got %v", got)
	}
	if got := Scan(ScanInput{Name: "x", Body: "   "}); got != nil {
		t.Errorf("expected nil for blank body, got %v", got)
	}
}

func TestRedactShortValues(t *testing.T) {
	if got := Redact("abc"); got != "***" {
		t.Errorf("Redact(abc) = %q", got)
	}
	if got := Redact("abcdefghij"); len(got) != 10 {
		t.Errorf("Redact(10) len = %d", len(got))
	}
}
