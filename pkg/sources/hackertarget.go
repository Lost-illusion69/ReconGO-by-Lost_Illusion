package sources

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// HackerTarget source
// ---------------------------------------------------------------------------

const (
	hackerTargetName    = "hackertarget"
	hackerTargetBaseURL = "https://api.hackertarget.com/hostsearch/?q=%s"
	hackerTargetTimeout = 10 * time.Second
)

// HackerTarget queries the HackerTarget API.
// It returns simple CSV-like text where each line is formatted as `subdomain,IP`.
type HackerTarget struct {
	client *http.Client
}

// NewHackerTarget returns a HackerTarget source ready for use.
func NewHackerTarget() *HackerTarget {
	return &HackerTarget{
		client: &http.Client{
			Timeout: hackerTargetTimeout,
		},
	}
}

// Name implements sources.Source.
func (h *HackerTarget) Name() string { return hackerTargetName }

// Fetch implements sources.Source.
func (h *HackerTarget) Fetch(domain string) ([]Result, error) {
	url := fmt.Sprintf(hackerTargetBaseURL, domain)

	ctx, cancel := context.WithTimeout(context.Background(), hackerTargetTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, WrapError(hackerTargetName, fmt.Errorf("building request: %w", err))
	}

	req.Header.Set("User-Agent", "ReconGo/1.0 (github.com/Lost-illusion69/recongo)")

	resp, err := h.client.Do(req)
	if err != nil {
		return nil, WrapError(hackerTargetName, fmt.Errorf("http request: %w", err))
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, WrapError(hackerTargetName, fmt.Errorf("unexpected status %d from HackerTarget", resp.StatusCode))
	}

	return h.parseAndDeduplicate(resp, domain), nil
}

// parseAndDeduplicate reads the plain-text response line-by-line.
func (h *HackerTarget) parseAndDeduplicate(resp *http.Response, domain string) []Result {
	seen := make(map[string]struct{})
	var results []Result

	suffix := "." + strings.ToLower(domain)
	exact := strings.ToLower(domain)

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()

		// Lines are typically format: "subdomain,IP"
		parts := strings.Split(line, ",")
		if len(parts) == 0 {
			continue
		}

		fqdn := strings.ToLower(strings.TrimSpace(parts[0]))
		if fqdn == "" {
			continue
		}

		// Discard entries that don't belong to the target domain
		if fqdn != exact && !strings.HasSuffix(fqdn, suffix) {
			continue
		}

		if _, already := seen[fqdn]; already {
			continue
		}
		seen[fqdn] = struct{}{}

		results = append(results, Result{
			Value:  fqdn,
			Source: hackerTargetName,
		})
	}

	return results
}
