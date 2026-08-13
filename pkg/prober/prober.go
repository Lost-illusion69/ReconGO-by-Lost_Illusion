// Package prober performs active HTTP/HTTPS web probing against resolved hosts.
//
// Design goals:
//   - Prefer HTTPS, fall back to plain HTTP on connection / TLS failure.
//   - Bound memory with a 1 MiB response body limit.
//   - Skip TLS certificate verification so self-signed targets are still probed.
package prober

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// maxBodyBytes caps how much of each response body we read.
// Large responses (file downloads, streaming endpoints) must not exhaust memory.
const maxBodyBytes = 1 << 20 // 1 MiB

// titleRe matches an HTML <title> element case-insensitively, including
// optional attributes on the opening tag.
var titleRe = regexp.MustCompile(`(?is)<title[^>]*>\s*(.*?)\s*</title>`)

// ---------------------------------------------------------------------------
// Result type
// ---------------------------------------------------------------------------

// AssetResult holds the outcome of a successful HTTP probe against a host.
type AssetResult struct {
	// Host is the subdomain / FQDN that was probed.
	Host string `json:"host"`

	// IPs are the previously resolved addresses for Host.
	// Populated by the probe worker; Probe itself leaves this nil.
	IPs []string `json:"ips"`

	// URL is the final scheme+host that responded (https preferred).
	URL string `json:"url"`

	// StatusCode is the HTTP response status (e.g. 200, 403, 500).
	StatusCode int `json:"status_code"`

	// Title is the extracted HTML <title> text, if present.
	Title string `json:"title"`

	// Server is the value of the Server response header.
	Server string `json:"server"`

	// ContentLength is the number of body bytes actually read (≤ 1 MiB).
	ContentLength int64 `json:"content_length"`

	// ResponseTime is the wall-clock duration of the successful request.
	ResponseTime time.Duration `json:"response_time_ns"`
}

// ---------------------------------------------------------------------------
// Probe
// ---------------------------------------------------------------------------

// Probe attempts an HTTPS request against host, falling back to HTTP when
// the TLS handshake or connection fails.  timeout applies to the entire
// round-trip (dial + TLS + headers + limited body read).
//
// On success it returns a populated AssetResult (IPs left unset).  On
// failure of both schemes it returns a non-nil error.
func Probe(host string, timeout time.Duration) (*AssetResult, error) {
	if host == "" {
		return nil, fmt.Errorf("prober: empty host")
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	client := newClient(timeout)

	// Prefer HTTPS; fall back to HTTP on transport-level failure.
	result, err := doProbe(client, "https", host)
	if err != nil {
		result, err = doProbe(client, "http", host)
		if err != nil {
			return nil, fmt.Errorf("prober: %s: https and http failed: %w", host, err)
		}
	}
	return result, nil
}

// newClient builds an http.Client with an insecure TLS transport and the
// supplied overall timeout.  Redirects are followed (Go default, up to 10).
func newClient(timeout time.Duration) *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			// Intentionally skip verify: recon targets frequently present
			// self-signed or mismatched certificates.  This is a probe tool,
			// not a browser trust store.
			InsecureSkipVerify: true, //nolint:gosec // intentional for recon probing
		},
		// Disable keep-alives so each probe releases its socket promptly
		// under high concurrency.
		DisableKeepAlives: true,
	}

	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}
}

// doProbe issues a single GET against scheme://host and builds an AssetResult.
func doProbe(client *http.Client, scheme, host string) (*AssetResult, error) {
	url := scheme + "://" + host

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	// Identify ourselves politely; some WAFs drop the default Go UA.
	req.Header.Set("User-Agent", "ReconGo/1.0 (+https://github.com/Lost-illusion69/recongo)")

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	limited := io.LimitReader(resp.Body, maxBodyBytes)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	elapsed := time.Since(start)

	return &AssetResult{
		Host:          host,
		URL:           url,
		StatusCode:    resp.StatusCode,
		Title:         extractTitle(body),
		Server:        resp.Header.Get("Server"),
		ContentLength: int64(len(body)),
		ResponseTime:  elapsed,
	}, nil
}

// extractTitle returns the first HTML <title> value found in body, or ""
// when none is present.  Matching is case-insensitive; surrounding whitespace
// is trimmed and internal whitespace is collapsed to a single space.
func extractTitle(body []byte) string {
	m := titleRe.FindSubmatch(body)
	if m == nil {
		return ""
	}
	raw := string(m[1])
	// Collapse whitespace / newlines that appear inside real-world titles.
	fields := strings.Fields(raw)
	return strings.Join(fields, " ")
}
