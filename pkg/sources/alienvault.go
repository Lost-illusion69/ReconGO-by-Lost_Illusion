// Package sources provides the AlienVault OTX passive DNS source.
//
// AlienVault Open Threat Exchange (OTX) is a free threat-intelligence platform
// that aggregates passive DNS data from millions of sensors worldwide.  Their
// public API requires no authentication for basic indicator lookups, making it
// an ideal reliable fallback when certificate-transparency APIs like crt.sh are
// temporarily unavailable.
//
// API reference:
//
//	GET https://otx.alienvault.com/api/v1/indicators/domain/<domain>/passive_dns
package sources

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// JSON response shape
// ---------------------------------------------------------------------------

// otxPassiveDNSResponse is the top-level object returned by the OTX passive
// DNS endpoint.  Only the fields we consume are declared.
//
// Example (truncated):
//
//	{
//	  "count": 42,
//	  "passive_dns": [
//	    {
//	      "indicator":  "tesla.com",
//	      "record_type":"A",
//	      "hostname":   "model3.tesla.com",
//	      "address":    "23.209.186.76",
//	      ...
//	    },
//	    ...
//	  ]
//	}
type otxPassiveDNSResponse struct {
	PassiveDNS []otxPassiveDNSEntry `json:"passive_dns"`
}

// otxPassiveDNSEntry represents a single passive DNS record.
type otxPassiveDNSEntry struct {
	// Hostname is the FQDN observed in the passive DNS record.
	Hostname string `json:"hostname"`
}

// ---------------------------------------------------------------------------
// AlienVault source
// ---------------------------------------------------------------------------

const (
	alienVaultName    = "alienvault"
	alienVaultBaseURL = "https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns"
	alienVaultTimeout = 10 * time.Second
)

// AlienVault queries the OTX passive DNS API to discover subdomains observed
// in real-world DNS traffic captured by OTX sensors.
//
// No API key is required for unauthenticated public lookups.
// Results are rate-limited server-side; add a key via the X-OTX-API-KEY
// header in future if higher rate limits are needed.
//
// AlienVault is safe for concurrent use — Fetch is stateless.
type AlienVault struct {
	client *http.Client
}

// NewAlienVault returns an AlienVault source ready for use.
func NewAlienVault() *AlienVault {
	return &AlienVault{
		client: &http.Client{
			Timeout: alienVaultTimeout,
		},
	}
}

// Name implements sources.Source.
func (a *AlienVault) Name() string { return alienVaultName }

// Fetch implements sources.Source.
//
// It queries the OTX passive DNS endpoint for domain, extracts hostname
// values, filters to confirmed subdomains of the target, and returns a
// deduplicated slice of Result values.
//
// Errors are wrapped with WrapError so the engine can log them without
// stopping the wider pipeline.
func (a *AlienVault) Fetch(domain string) ([]Result, error) {
	url := fmt.Sprintf(alienVaultBaseURL, domain)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, WrapError(alienVaultName, fmt.Errorf("building request: %w", err))
	}

	req.Header.Set("User-Agent", "ReconGo/1.0 (github.com/Lost-illusion69/recongo)")
	req.Header.Set("Accept", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, WrapError(alienVaultName, fmt.Errorf("http request: %w", err))
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, WrapError(alienVaultName,
			fmt.Errorf("unexpected status %d from OTX API", resp.StatusCode))
	}

	var payload otxPassiveDNSResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, WrapError(alienVaultName, fmt.Errorf("json decode: %w", err))
	}

	return a.deduplicate(payload.PassiveDNS, domain), nil
}

// deduplicate normalises and deduplicates the hostname values extracted from
// the OTX passive DNS response, keeping only confirmed subdomains of domain.
func (a *AlienVault) deduplicate(entries []otxPassiveDNSEntry, domain string) []Result {
	seen := make(map[string]struct{}, len(entries))
	results := make([]Result, 0, len(entries))

	suffix := "." + strings.ToLower(domain)
	exact := strings.ToLower(domain)

	for _, entry := range entries {
		fqdn := strings.ToLower(strings.TrimSpace(entry.Hostname))
		if fqdn == "" {
			continue
		}

		// Discard entries that don't belong to the target domain.
		if fqdn != exact && !strings.HasSuffix(fqdn, suffix) {
			continue
		}

		if _, already := seen[fqdn]; already {
			continue
		}
		seen[fqdn] = struct{}{}

		results = append(results, Result{
			Value:  fqdn,
			Source: alienVaultName,
		})
	}

	return results
}
