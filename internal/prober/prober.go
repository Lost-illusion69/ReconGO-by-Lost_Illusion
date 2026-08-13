package prober

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Lost-illusion69/recongo/internal/mmh3"
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

	result, baseURL, body, err := doProbe(client, opts, "https", host)
	if err != nil {
		result, baseURL, body, err = doProbe(client, opts, "http", host)
		if err != nil {
			return nil, fmt.Errorf("prober: %s: https and http failed: %w", host, err)
		}
	}

	result.BodyMMH3 = mmh3.Hash(body)
	result.Endpoints = MineEndpoints(body)
	if favicon, err := fetchFavicon(client, opts, baseURL, body); err == nil && len(favicon) > 0 {
		result.FaviconMMH3 = mmh3.FaviconHash(favicon)
	}

	return result, nil
}

func doProbe(client *http.Client, opts Options, scheme, host string) (*models.Result, *url.URL, []byte, error) {
	applyDelay(opts.Delay)

	rawURL := scheme + "://" + host
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, nil, nil, err
	}
	applyHeaders(req, opts)

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, nil, err
	}
	defer resp.Body.Close()

	body, err := readLimitedBody(resp.Body, maxBodyBytes)
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

func fetchFavicon(client *http.Client, opts Options, base *url.URL, body []byte) ([]byte, error) {
	iconPath := findIconHref(body)
	if iconPath == "" {
		iconPath = "/favicon.ico"
	}

	iconURL, err := base.Parse(iconPath)
	if err != nil {
		return nil, err
	}

	applyDelay(opts.Delay)

	req, err := http.NewRequest(http.MethodGet, iconURL.String(), nil)
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
		return nil, fmt.Errorf("favicon status %d", resp.StatusCode)
	}
	return readLimitedBody(resp.Body, 256*1024)
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
