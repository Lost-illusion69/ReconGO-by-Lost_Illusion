package prober

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Lost-illusion69/recongo/internal/mmh3"
	"github.com/Lost-illusion69/recongo/internal/origin"
	"github.com/Lost-illusion69/recongo/models"
)

// Probe attempts HTTPS then HTTP against host using the supplied options.
func Probe(host string, opts Options) (*models.Result, error) {
	if host == "" {
		return nil, fmt.Errorf("prober: empty host")
	}

	opts = opts.withDefaults()
	client, err := newClient(opts)
	if err != nil {
		return nil, err
	}

	result, baseURL, body, respHeader, err := doProbe(client, opts, "https", host)
	if err != nil {
		result, baseURL, body, respHeader, err = doProbe(client, opts, "http", host)
		if err != nil {
			return nil, fmt.Errorf("prober: %s: https and http failed: %w", host, err)
		}
	}

	result.BodyMMH3 = mmh3.Hash(body)

	jsOpts := defaultJSFetchOptions()
	ctx, cancel := context.WithTimeout(context.Background(), opts.Timeout)
	defer cancel()
	pageHTML := string(body)
	jsURLs := extractJSURLs(pageHTML, baseURL.String())
	jsBodies := fetchJSBodies(ctx, client, baseURL.String(), pageHTML, jsOpts)

	bodies := []string{pageHTML}
	bodies = append(bodies, jsBodies...)
	result.Endpoints = MineEndpoints(bodies...)

	if opts.Verbose {
		fmt.Fprintf(os.Stderr, "  [js] %s: %d script ref(s), fetched %d bundle(s), mined %d endpoint(s)\n",
			host, len(jsURLs), len(jsBodies), len(result.Endpoints))
	}

	if favicon, err := fetchFavicon(client, opts, baseURL, body); err == nil && len(favicon) > 0 {
		result.FaviconMMH3 = mmh3.FaviconHash(favicon)
	}

	if opts.FindOrigin {
		fetch := func(ctx context.Context, target string) (int32, error) {
			icon, err := fetchFaviconFromHost(client, opts, target)
			if err != nil || len(icon) == 0 {
				return 0, err
			}
			return mmh3.FaviconHash(icon), nil
		}
		origin.EnrichResult(result, respHeader, opts.OriginFindings, true, fetch)
	}

	ensureSliceFields(result)
	return result, nil
}

func doProbe(client *http.Client, opts Options, scheme, host string) (*models.Result, *url.URL, []byte, http.Header, error) {
	waitForHost(host)

	rawURL := scheme + "://" + host
	var lastHeader http.Header

	for attempt := 0; attempt < maxProbeRetries; attempt++ {
		applyDelay(opts.Delay)

		req, err := http.NewRequest(http.MethodGet, rawURL, nil)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		applyHeaders(req, opts)

		start := time.Now()
		resp, err := client.Do(req)
		if err != nil {
			return nil, nil, nil, nil, err
		}

		body, err := readLimitedBody(resp.Body, maxBodyBytes)
		resp.Body.Close()
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("read body: %w", err)
		}

		lastHeader = resp.Header.Clone()

		if shouldRetryStatus(resp.StatusCode) && attempt < maxProbeRetries-1 {
			delay := recordRateLimit(host)
			if opts.Verbose {
				fmt.Fprintf(os.Stderr, "  [backoff] %s: HTTP %d, retry in %s\n", host, resp.StatusCode, delay)
			}
			time.Sleep(delay)
			continue
		}

		resetBackoff(host)
		parsed, _ := url.Parse(rawURL)
		return &models.Result{
			Host:          host,
			URL:           rawURL,
			StatusCode:    resp.StatusCode,
			Title:         ExtractTitle(body),
			Server:        resp.Header.Get("Server"),
			ContentLength: int64(len(body)),
			ResponseTime:  time.Since(start),
		}, parsed, body, lastHeader, nil
	}

	return nil, nil, nil, nil, fmt.Errorf("exhausted retries for %s", host)
}

func fetchFavicon(client *http.Client, opts Options, base *url.URL, body []byte) ([]byte, error) {
	iconPath := findIconHref(body)
	if iconPath == "" {
		iconPath = "/favicon.ico"
	}
	iconURL, err := base.Parse(iconPath)
	if err != nil {
		return nil, err
	}
	return fetchURLBytes(client, opts, iconURL.String(), 256*1024)
}

func fetchFaviconFromHost(client *http.Client, opts Options, host string) ([]byte, error) {
	for _, scheme := range []string{"https", "http"} {
		raw := scheme + "://" + host + "/favicon.ico"
		b, err := fetchURLBytes(client, opts, raw, 256*1024)
		if err == nil && len(b) > 0 {
			return b, nil
		}
	}
	return nil, fmt.Errorf("favicon unavailable for %s", host)
}

func fetchURLBytes(client *http.Client, opts Options, rawURL string, limit int) ([]byte, error) {
	applyDelay(opts.Delay)
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	applyHeaders(req, opts)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	return readLimitedBody(resp.Body, int64(limit))
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

func ensureSliceFields(r *models.Result) {
	if r.Endpoints == nil {
		r.Endpoints = []string{}
	}
	if r.HistoricalURLs == nil {
		r.HistoricalURLs = []string{}
	}
	if r.DiscoveredParams == nil {
		r.DiscoveredParams = []string{}
	}
	if r.PotentialOriginIPs == nil {
		r.PotentialOriginIPs = []string{}
	}
}
