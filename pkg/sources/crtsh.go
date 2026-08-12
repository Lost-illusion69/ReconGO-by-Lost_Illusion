// Package sources provides the crt.sh certificate transparency source.
//
// crt.sh is a public service by Sectigo that exposes Certificate Transparency
// log data via a free JSON API.  Querying for "%.domain.com" returns all
// certificates that contain any subdomain of domain.com in the SAN or CN field,
// which is one of the richest passive subdomain enumeration sources available.
//
// API reference: https://crt.sh/?q=%25.<domain>&output=json
package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// JSON response shape
// ---------------------------------------------------------------------------

// crtShEntry mirrors a single object in the crt.sh JSON array response.
// Only the fields we actually use are declared; the rest are discarded by
// the JSON decoder automatically.
//
// Example raw entry:
//
//	{
//	  "issuer_ca_id": 183267,
//	  "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
//	  "common_name":  "api.example.com",
//	  "name_value":   "api.example.com\nwww.api.example.com",
//	  "id":           9876543210,
//	  "entry_timestamp": "2024-01-15T10:30:00.000",
//	  "not_before":   "2024-01-15T10:30:00",
//	  "not_after":    "2024-04-15T10:30:00"
//	}
type crtShEntry struct {
	// NameValue may contain multiple FQDNs separated by newlines,
	// and may include wildcard entries such as "*.example.com".
	NameValue string `json:"name_value"`
}

// ---------------------------------------------------------------------------
// CrtSh source
// ---------------------------------------------------------------------------

const (
	crtShName    = "crtsh"
	crtShBaseURL = "https://crt.sh/"
	crtShTimeout = 10 * time.Second
)

// CrtSh queries the crt.sh Certificate Transparency search API to discover
// subdomains recorded in public TLS certificates.
//
// It is safe for concurrent use — Fetch is stateless and each call
// creates its own HTTP request.
type CrtSh struct {
	// client is an HTTP client with a sensible timeout.
	// Using the package-level http.DefaultClient is intentionally avoided
	// because it has no timeout and can block indefinitely.
	client *http.Client
}

// NewCrtSh returns a CrtSh source ready for use.
func NewCrtSh() *CrtSh {
	return &CrtSh{
		client: &http.Client{
			Timeout: crtShTimeout,
		},
	}
}

// Name implements sources.Source.
func (c *CrtSh) Name() string { return crtShName }

// Fetch implements sources.Source.
//
// It queries crt.sh for all certificates issued for subdomains of domain,
// extracts the FQDN values from each certificate's SAN/CN fields, strips
// wildcards, and returns a deduplicated slice of Result values.
//
// On HTTP or JSON errors it returns a wrapped SourceError so the engine
// can log the failure without stopping the pipeline.
func (c *CrtSh) Fetch(domain string) ([]Result, error) {
	url := fmt.Sprintf("%s?q=%%.%s&output=json", crtShBaseURL, domain)

	// Use a context with our own timeout so we are not reliant solely on the
	// http.Client.Timeout (which only covers the total round-trip, not stalls
	// during the response body read on slow connections).
	ctx, cancel := context.WithTimeout(context.Background(), crtShTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, WrapError(crtShName, fmt.Errorf("building request: %w", err))
	}

	// Identify ourselves to crt.sh with a descriptive User-Agent so their
	// operators can distinguish legitimate tool traffic from abuse.
	req.Header.Set("User-Agent", "ReconGo/1.0 (github.com/Lost-illusion69/recongo)")
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, WrapError(crtShName, fmt.Errorf("http request: %w", err))
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, WrapError(crtShName, fmt.Errorf("unexpected status %d from crt.sh", resp.StatusCode))
	}

	// Decode the JSON array directly from the response body stream to avoid
	// holding the entire payload in memory as a []byte.
	var entries []crtShEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, WrapError(crtShName, fmt.Errorf("json decode: %w", err))
	}

	return c.deduplicate(entries, domain), nil
}

// deduplicate extracts, normalises, and deduplicates FQDNs from the crt.sh
// response entries.
//
// crt.sh returns many duplicate rows because the same domain often appears
// across hundreds of certificate renewals.  Each NameValue field can also
// contain multiple newline-separated FQDNs and wildcard entries ("*.foo.com").
// We:
//  1. Split multi-value NameValue on newlines.
//  2. Strip leading "*." from wildcard entries to get the base FQDN.
//  3. Normalise to lowercase.
//  4. Skip entries that are not subdomains of the target domain.
//  5. Deduplicate via a map.
func (c *CrtSh) deduplicate(entries []crtShEntry, domain string) []Result {
	seen := make(map[string]struct{}, len(entries))
	results := make([]Result, 0, len(entries))

	suffix := "." + strings.ToLower(domain)
	exact := strings.ToLower(domain)

	for _, entry := range entries {
		// Each NameValue can be a newline-delimited list of FQDNs.
		for _, raw := range strings.Split(entry.NameValue, "\n") {
			fqdn := strings.ToLower(strings.TrimSpace(raw))

			// Strip wildcard prefix so "*.api.example.com" → "api.example.com".
			fqdn = strings.TrimPrefix(fqdn, "*.")

			if fqdn == "" {
				continue
			}

			// Only keep subdomains that actually belong to the target domain.
			if fqdn != exact && !strings.HasSuffix(fqdn, suffix) {
				continue
			}

			// Deduplicate.
			if _, already := seen[fqdn]; already {
				continue
			}
			seen[fqdn] = struct{}{}

			results = append(results, Result{
				Value:  fqdn,
				Source: crtShName,
			})
		}
	}

	return results
}
