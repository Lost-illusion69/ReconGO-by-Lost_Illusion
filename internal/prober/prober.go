// Package prober performs HTTP probing with Shodan-compatible MMH3 fingerprints.
package prober

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/Lost-illusion69/recongo/internal/mmh3"
	"github.com/Lost-illusion69/recongo/models"
)

const maxBodyBytes = 1 << 20 // 1 MiB

// MaxBodyBytes is exported for the pkg/prober wrapper.
const MaxBodyBytes = maxBodyBytes

var (
	titleRe = regexp.MustCompile(`(?is)<title[^>]*>\s*(.*?)\s*</title>`)
	iconRe  = regexp.MustCompile(`(?is)<link[^>]+rel=["']?(?:shortcut\s+icon|icon)["']?[^>]+href=["']([^"']+)["']`)
	iconRe2 = regexp.MustCompile(`(?is)<link[^>]+href=["']([^"']+)["'][^>]+rel=["']?(?:shortcut\s+icon|icon)["']?`)
)

// Probe attempts HTTPS then HTTP against host, computing body and favicon MMH3 hashes.
func Probe(host string, timeout time.Duration) (*models.Result, error) {
	if host == "" {
		return nil, fmt.Errorf("prober: empty host")
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	client := newClient(timeout)

	result, baseURL, body, err := doProbe(client, "https", host)
	if err != nil {
		result, baseURL, body, err = doProbe(client, "http", host)
		if err != nil {
			return nil, fmt.Errorf("prober: %s: https and http failed: %w", host, err)
		}
	}

	result.BodyMMH3 = mmh3.Hash(body)
	if favicon, err := fetchFavicon(client, baseURL, body); err == nil && len(favicon) > 0 {
		result.FaviconMMH3 = mmh3.FaviconHash(favicon)
	}

	return result, nil
}

func newClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec // intentional for recon probing
			},
			DisableKeepAlives: true,
		},
	}
}

func doProbe(client *http.Client, scheme, host string) (*models.Result, *url.URL, []byte, error) {
	rawURL := scheme + "://" + host
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, nil, nil, err
	}
	req.Header.Set("User-Agent", "ReconGo/1.0 (+https://github.com/Lost-illusion69/recongo)")

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("read body: %w", err)
	}

	parsed, _ := url.Parse(rawURL)
	return &models.Result{
		Host:          host,
		URL:           rawURL,
		StatusCode:    resp.StatusCode,
		Title:         ExtractTitle(body),
		Server:        resp.Header.Get("Server"),
		ContentLength: int64(len(body)),
		ResponseTime:  time.Since(start),
	}, parsed, body, nil
}

func fetchFavicon(client *http.Client, base *url.URL, body []byte) ([]byte, error) {
	iconPath := findIconHref(body)
	if iconPath == "" {
		iconPath = "/favicon.ico"
	}

	iconURL, err := base.Parse(iconPath)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), client.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, iconURL.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "ReconGo/1.0 (+https://github.com/Lost-illusion69/recongo)")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("favicon status %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 256*1024))
}

func findIconHref(body []byte) string {
	if m := iconRe.FindSubmatch(body); len(m) > 1 {
		return strings.TrimSpace(string(m[1]))
	}
	if m := iconRe2.FindSubmatch(body); len(m) > 1 {
		return strings.TrimSpace(string(m[1]))
	}
	return ""
}

// ExtractTitle returns the first HTML title in body.
func ExtractTitle(body []byte) string {
	m := titleRe.FindSubmatch(body)
	if m == nil {
		return ""
	}
	return strings.Join(strings.Fields(string(m[1])), " ")
}
