package prober

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

const (
	defaultMaxJSFiles   = 8
	defaultMaxJSBytes   = 512 * 1024
	defaultJSFetchSlots = 4
)

// JSFetchOptions controls optional JavaScript bundle mining.
type JSFetchOptions struct {
	Enabled   bool
	MaxFiles  int
	MaxBytes  int
	Parallel  int
}

func defaultJSFetchOptions() JSFetchOptions {
	return JSFetchOptions{
		Enabled:  true,
		MaxFiles: defaultMaxJSFiles,
		MaxBytes: defaultMaxJSBytes,
		Parallel: defaultJSFetchSlots,
	}
}

// extractJSURLs finds script references in HTML and resolves them against baseURL.
func extractJSURLs(html, baseURL string) []string {
	base, err := url.Parse(baseURL)
	if err != nil {
		return nil
	}

	seen := make(map[string]struct{})
	var out []string

	add := func(raw string) {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return
		}
		lower := strings.ToLower(raw)
		if strings.HasPrefix(lower, "data:") || strings.HasPrefix(lower, "javascript:") {
			return
		}
		if !strings.Contains(lower, ".js") && !strings.Contains(lower, "/js/") && !strings.Contains(lower, "bundle") && !strings.Contains(lower, "chunk") {
			return
		}
		u, err := url.Parse(raw)
		if err != nil {
			return
		}
		resolved := base.ResolveReference(u).String()
		if _, ok := seen[resolved]; ok {
			return
		}
		seen[resolved] = struct{}{}
		out = append(out, resolved)
	}

	for _, m := range jsRefRe.FindAllStringSubmatch(html, -1) {
		if len(m) > 1 {
			add(m[1])
		}
	}

	// Inline module/import hints in HTML (no fetch, but path strings help mining).
	for _, m := range jsImportRe.FindAllStringSubmatch(html, -1) {
		if len(m) > 1 {
			add(m[1])
		}
	}

	return out
}

// fetchJSBodies downloads up to MaxFiles script bodies for endpoint mining.
func fetchJSBodies(ctx context.Context, client *http.Client, baseURL, html string, opts JSFetchOptions) []string {
	if !opts.Enabled {
		return nil
	}
	if opts.MaxFiles <= 0 {
		opts.MaxFiles = defaultMaxJSFiles
	}
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = defaultMaxJSBytes
	}
	if opts.Parallel <= 0 {
		opts.Parallel = defaultJSFetchSlots
	}

	urls := extractJSURLs(html, baseURL)
	if len(urls) == 0 {
		return nil
	}
	if len(urls) > opts.MaxFiles {
		urls = urls[:opts.MaxFiles]
	}

	type item struct {
		idx  int
		body string
	}

	ch := make(chan item, len(urls))
	sem := make(chan struct{}, opts.Parallel)
	var wg sync.WaitGroup

	for i, u := range urls {
		wg.Add(1)
		go func(idx int, scriptURL string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			body, err := fetchScriptBody(ctx, client, scriptURL, opts.MaxBytes)
			if err != nil || body == "" {
				return
			}
			ch <- item{idx: idx, body: body}
		}(i, u)
	}

	wg.Wait()
	close(ch)

	ordered := make([]string, len(urls))
	for it := range ch {
		ordered[it.idx] = it.body
	}

	var bodies []string
	for _, b := range ordered {
		if b != "" {
			bodies = append(bodies, b)
		}
	}
	return bodies
}

func fetchScriptBody(ctx context.Context, client *http.Client, scriptURL string, maxBytes int) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, scriptURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/javascript, text/javascript, */*;q=0.8")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("status %d", resp.StatusCode)
	}

	limited := io.LimitReader(resp.Body, int64(maxBytes)+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return "", err
	}
	if len(data) > maxBytes {
		data = data[:maxBytes]
	}
	return string(data), nil
}
