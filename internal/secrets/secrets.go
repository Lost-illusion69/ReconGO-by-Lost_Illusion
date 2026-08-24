// Package secrets scans HTML/JS bodies for high-signal credential material
// exposed in client-side code: cloud keys, tokens, webhooks, and private keys.
//
// Findings are redacted by default so pipelines can log and report them without
// leaking the underlying secret on disk or in notifications.
package secrets

import (
	"regexp"
	"strings"
)

// Confidence tiers used to rank findings.
type Confidence string

const (
	High   Confidence = "high"
	Medium Confidence = "medium"
	Low    Confidence = "low"
)

// Finding is a single detected credential candidate.
type Finding struct {
	Kind       string     `json:"kind"`
	Confidence Confidence `json:"confidence"`
	Value      string     `json:"value"`  // redacted for safe reporting
	Source     string     `json:"source"` // body label, e.g. "html" or "js/0"
	Context    string     `json:"context,omitempty"`
}

// ScanInput pairs a body with a label so findings can be attributed.
type ScanInput struct {
	Name string
	Body string
}

// rule is a compiled detection pattern plus policy.
type rule struct {
	kind       string
	confidence Confidence
	re         *regexp.Regexp
	// group selects which capture group holds the credential (0 = whole match).
	group int
	// skip is a risk filter for obviously synthetic values.
	skip func(string) bool
}

// Redact masks a secret, keeping only a 4-character tail fingerprint so
// duplicate findings can be correlated without leaking the credential.
func Redact(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	if strings.Contains(v, "\n") {
		// Multi-line blocks (PEM keys): keep the header and a checksum-ish tail.
		first := strings.SplitN(v, "\n", 2)[0]
		return first + " …<redacted>…"
	}
	l := len(v)
	if l <= 8 {
		return strings.Repeat("*", l)
	}
	return strings.Repeat("*", l-4) + v[l-4:]
}

// patterns lists the high-signal credential classes most commonly left in
// client-side code (ordered so more specific rules win the dedupe pass).
var patterns = []rule{
	{
		kind: "aws-access-key", confidence: High,
		re:   regexp.MustCompile(`(?:AKIA|ASIA)[0-9A-Z]{16}`),
		skip: func(s string) bool { return strings.Contains(s, "XXXX") },
	},
	{
		kind: "aws-secret-key", confidence: High,
		re:    regexp.MustCompile(`(?i)(?:aws[_-]?secret[_-]?access[_-]?key|aws[_-]?secret[_-]?key)\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?`),
		group: 1,
	},
	{
		kind: "github-token", confidence: High,
		re: regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36,200}|github_pat_[A-Za-z0-9_]{22,200}`),
	},
	{
		kind: "slack-webhook", confidence: High,
		re:   regexp.MustCompile(`https://hooks\.slack\.com/services/[A-Z0-9]{9,12}/[A-Z0-9]{9,12}/[A-Za-z0-9]{20,64}`),
		skip: func(s string) bool { return strings.Contains(strings.ToLower(s), "example") },
	},
	{
		kind: "slack-token", confidence: High,
		re: regexp.MustCompile(`xox[baprs]-[A-Za-z0-9]{10,64}`),
	},
	{
		kind: "google-api-key", confidence: High,
		re: regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`),
	},
	{
		kind: "stripe-key", confidence: High,
		re: regexp.MustCompile(`[rs]k_(?:live|test)_[0-9A-Za-z]{20,64}`),
	},
	{
		kind: "twilio-key", confidence: High,
		re: regexp.MustCompile(`SK[0-9a-fA-F]{32}`),
	},
	{
		kind: "sendgrid-api-key", confidence: High,
		re: regexp.MustCompile(`SG\.[A-Za-z0-9]{16,22}\.[A-Za-z0-9]{40,48}`),
	},
	{
		kind: "npm-token", confidence: Medium,
		re: regexp.MustCompile(`(?:npm_[A-Za-z0-9]{36}|_authToken=[A-Za-z0-9\-_]{20,})`),
	},
	{
		kind: "private-key", confidence: High,
		re: regexp.MustCompile(`-----BEGIN(?: [A-Z0-9 ]+)?PRIVATE KEY(?: BLOCK)?-----`),
	},
	{
		kind: "jwt", confidence: Medium,
		re: regexp.MustCompile(`eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}`),
	},
	{
		kind: "generic-secret", confidence: Low,
		re:    regexp.MustCompile(`(?i)(api[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|passwd|password)\s*[:=]\s*["']?([A-Za-z0-9_\-+/=]{20,120})["']?`),
		group: 2,
		skip: func(s string) bool {
			low := strings.ToLower(s)
			return strings.Contains(low, "example") || strings.Contains(low, "placeholder") ||
				strings.Contains(low, "xxxx") || strings.Contains(low, "changeme") ||
				strings.Contains(low, "your_") || strings.Contains(low, "replace")
		},
	},
}

// Scan runs all detection rules across the supplied bodies, returning
// deduplicated, redacted findings sorted by confidence then kind.
func Scan(inputs ...ScanInput) []Finding {
	if len(inputs) == 0 {
		return nil
	}

	var out []Finding
	seen := make(map[string]struct{})

	for _, in := range inputs {
		if strings.TrimSpace(in.Body) == "" {
			continue
		}
		for _, r := range patterns {
			for _, m := range r.re.FindAllStringSubmatch(in.Body, -1) {
				val := m[0]
				if r.group > 0 && r.group < len(m) && m[r.group] != "" {
					val = m[r.group]
				}
				if r.skip != nil && r.skip(val) {
					continue
				}
				mask := Redact(val)
				if mask == "" {
					continue
				}
				// Dedupe identical redacted values per source body.
				key := in.Name + "|" + r.kind + "|" + mask
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
				out = append(out, Finding{
					Kind:       r.kind,
					Confidence: r.confidence,
					Value:      mask,
					Source:     in.Name,
					Context:    excerptAround(in.Body, val),
				})
			}
		}
	}

	rank := map[Confidence]int{High: 0, Medium: 1, Low: 2}
	sortSlice(out, func(a, b Finding) bool {
		if rank[a.Confidence] != rank[b.Confidence] {
			return rank[a.Confidence] < rank[b.Confidence]
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.Value < b.Value
	})
	return out
}

// excerptAround returns a bounded snippet of body surrounding the match for
// triage context (line-aware, compact).
func excerptAround(body, needle string) string {
	idx := strings.Index(body, needle)
	if idx < 0 {
		return ""
	}
	const radius = 60
	start := idx - radius
	if start < 0 {
		start = 0
	}
	end := idx + len(needle) + radius
	if end > len(body) {
		end = len(body)
	}
	s := strings.ReplaceAll(body[start:end], "\n", " ")
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 160 {
		s = s[:160] + "…"
	}
	return s
}

// sortSlice keeps Scan dependency-light; findings per host are small.
func sortSlice(s []Finding, less func(a, b Finding) bool) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && less(s[j], s[j-1]); j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
