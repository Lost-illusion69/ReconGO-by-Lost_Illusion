package prober

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Lost-illusion69/recongo/internal/cors"
	"github.com/Lost-illusion69/recongo/internal/mmh3"
	"github.com/Lost-illusion69/recongo/internal/origin"
	recsecrets "github.com/Lost-illusion69/recongo/internal/secrets"
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

	if opts.ScanSecrets {
		result.Secrets = scanBodies(pageHTML, jsBodies)
		if opts.Verbose {
			fmt.Fprintf(os.Stderr, "  [secrets] %s: %d credential candidate(s) scanned\n", host, len(result.Secrets))
		}
	}

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

	if opts.ScanCORS {
		findings := cors.Check(ctx, baseURL.String(), host, corsProbeFunc(client, opts))
		result.CORS = mapCORSFindings(findings)
		if opts.Verbose && len(result.CORS) > 0 {
			fmt.Fprintf(os.Stderr, "  [cors] %s: %d misconfiguration(s) found\n", host, len(result.CORS))
		}
	}

	ensureSliceFields(result)
	return result, nil
}

// FetchBody performs a best-effort GET (HTTPS then HTTP) against host and
// returns the response body as text, independent of Probe's own request.
// Used for auxiliary confirmatory checks that run after the main probe stage
// (e.g. subdomain-takeover fingerprint verification).
func FetchBody(host string, opts Options) (string, error) {
	opts = opts.withDefaults()
	client, err := newClient(opts)
	if err != nil {
		return "", err
	}
	for _, scheme := range []string{"https", "http"} {
		req, err := http.NewRequest(http.MethodGet, scheme+"://"+host, nil)
		if err != nil {
			continue
		}
		applyHeaders(req, opts)
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, err := readLimitedBody(resp.Body, maxBodyBytes)
		resp.Body.Close()
		if err != nil {
			continue
		}
		return string(body), nil
	}
	return "", fmt.Errorf("prober: fetch body failed for %s", host)
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

// corsProbeFunc adapts the shared HTTP client into a cors.ProbeFunc, sending
// the candidate Origin header and reporting back the CORS-relevant response
// headers. It reuses opts' headers/proxy/UA config so CORS probes look like
// any other probe request.
func corsProbeFunc(client *http.Client, opts Options) cors.ProbeFunc {
	return func(ctx context.Context, target, origin string) (cors.Response, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			return cors.Response{}, err
		}
		applyHeaders(req, opts)
		req.Header.Set("Origin", origin)

		resp, err := client.Do(req)
		if err != nil {
			return cors.Response{}, err
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxBodyBytes))

		return cors.Response{
			StatusCode: resp.StatusCode,
			ACAO:       resp.Header.Get("Access-Control-Allow-Origin"),
			ACAC:       resp.Header.Get("Access-Control-Allow-Credentials"),
		}, nil
	}
}

// mapCORSFindings converts internal/cors findings to the shared model type.
func mapCORSFindings(findings []cors.Finding) []models.CORSFinding {
	if len(findings) == 0 {
		return []models.CORSFinding{}
	}
	out := make([]models.CORSFinding, 0, len(findings))
	for _, f := range findings {
		out = append(out, models.CORSFinding{
			SentOrigin:       f.SentOrigin,
			Reflected:        f.Reflected,
			AllowCredentials: f.AllowCredentials,
			Severity:         string(f.Severity),
			Note:             f.Note,
		})
	}
	return out
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
	if r.FuzzResults == nil {
		r.FuzzResults = []models.FuzzHit{}
	}
	if r.Secrets == nil {
		r.Secrets = []models.SecretFinding{}
	}
	if r.CORS == nil {
		r.CORS = []models.CORSFinding{}
	}
}

// scanBodies runs credential detection over the page and any fetched JS, then
// maps the redacted findings onto the shared model type.
func scanBodies(pageHTML string, jsBodies []string) []models.SecretFinding {
	inputs := []recsecrets.ScanInput{{Name: "html", Body: pageHTML}}
	for i, b := range jsBodies {
		inputs = append(inputs, recsecrets.ScanInput{Name: fmt.Sprintf("js/%d", i), Body: b})
	}
	raw := recsecrets.Scan(inputs...)
	if len(raw) == 0 {
		return []models.SecretFinding{}
	}
	out := make([]models.SecretFinding, 0, len(raw))
	for _, f := range raw {
		out = append(out, models.SecretFinding{
			Kind:       f.Kind,
			Confidence: string(f.Confidence),
			Value:      f.Value,
			Source:     f.Source,
			Context:    f.Context,
		})
	}
	return out
}
