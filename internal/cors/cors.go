// Package cors detects permissive cross-origin resource sharing
// configurations on live web apps by reflecting attacker-controlled origins.
//
// Only exploitable or notable misconfigurations are reported (high/medium);
// wildcard `Access-Control-Allow-Origin: *` is intentionally skipped because it
// is ubiquitous on public APIs and is not exploitable with credentials.
package cors

import (
	"context"
	"strings"
)

// Severity ranks a CORS misconfiguration by real-world exploitability.
type Severity string

const (
	// High means an arbitrary origin is reflected together with credentials,
	// enabling a full authenticated cross-origin read.
	High Severity = "high"
	// Medium means an arbitrary origin is reflected without credentials —
	// exploitable against unauthenticated endpoints — or a null origin is
	// reflected (with or without credentials), since null exploitation
	// requires a sandboxed iframe / local-file context.
	Medium Severity = "medium"
	// Low marks informational configurations (wildcard ACAO). Not reported.
	Low Severity = "low"
)

// Response captures the CORS-relevant facts of a probe request.
type Response struct {
	StatusCode int
	ACAO       string // Access-Control-Allow-Origin
	ACAC       string // Access-Control-Allow-Credentials
}

// ProbeFunc issues a GET against target carrying the supplied Origin header.
type ProbeFunc func(ctx context.Context, target, origin string) (Response, error)

// Finding is a single confirmed CORS misconfiguration.
type Finding struct {
	SentOrigin       string   `json:"sent_origin"`
	Reflected        string   `json:"reflected_origin"`
	AllowCredentials bool     `json:"allow_credentials"`
	Severity         Severity `json:"severity"`
	Note             string   `json:"note,omitempty"`
}

// Check reflects a curated set of attacker origins against baseURL and
// returns notable misconfigurations sorted by severity. A nil or erroring
// probe simply contributes no finding, so partial transport failures never
// abort the sweep.
func Check(ctx context.Context, baseURL, host string, probe ProbeFunc) []Finding {
	if ctx.Err() != nil {
		return nil
	}
	if strings.TrimSpace(baseURL) == "" || probe == nil {
		return nil
	}

	var out []Finding
	for _, atk := range attackOrigins(host) {
		if ctx.Err() != nil {
			return out
		}
		resp, err := probe(ctx, baseURL, atk.value)
		if err != nil {
			continue
		}
		f := classify(atk.value, resp.ACAO, resp.ACAC, atk.note)
		if f == nil {
			continue
		}
		out = append(out, *f)
	}

	rank := map[Severity]int{High: 0, Medium: 1, Low: 2}
	sortSlice(out, func(a, b Finding) bool {
		if rank[a.Severity] != rank[b.Severity] {
			return rank[a.Severity] < rank[b.Severity]
		}
		return a.SentOrigin < b.SentOrigin
	})
	return out
}

// sortSlice keeps the package dependency-light; findings per host are small.
func sortSlice(s []Finding, less func(a, b Finding) bool) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && less(s[j], s[j-1]); j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// attackOrigin is one crafted Origin value plus the technique it exercises.
type attackOrigin struct {
	value string
	note  string
}

// attackOrigins returns the crafted origins worth testing for a given host.
func attackOrigins(host string) []attackOrigin {
	host = strings.TrimSpace(host)
	return []attackOrigin{
		{value: "https://evil.example", note: "arbitrary origin reflection"},
		{value: "null", note: "null origin reflected (sandboxed iframe / local file)"},
		{value: "https://" + host + ".evil.example", note: "trusted-suffix bypass"},
	}
}

// classify maps a probe response to a finding, or nil when the configuration
// is not notable.
func classify(sent, acao, acac, note string) *Finding {
	acao = strings.TrimSpace(acao)
	acac = strings.TrimSpace(acac)
	creds := strings.EqualFold(acac, "true")

	// Null-origin reflection stays medium even with credentials: exploitation
	// requires a sandboxed iframe or local-file context, which caps real-world
	// impact below arbitrary-origin reflection. This must precede the generic
	// exact-match branch or it would never be reached.
	if strings.EqualFold(sent, "null") && strings.EqualFold(acao, "null") {
		return &Finding{
			SentOrigin:       sent,
			Reflected:        acao,
			AllowCredentials: creds,
			Severity:         Medium,
			Note:             note,
		}
	}

	switch {
	case strings.EqualFold(acao, sent):
		if creds {
			return &Finding{
				SentOrigin:       sent,
				Reflected:        acao,
				AllowCredentials: true,
				Severity:         High,
				Note:             note + " with credentials — full authenticated cross-origin read",
			}
		}
		return &Finding{
			SentOrigin:       sent,
			Reflected:        acao,
			AllowCredentials: false,
			Severity:         Medium,
			Note:             note,
		}
	default:
		// Wildcard or absent ACAO: not notable.
		return nil
	}
}
