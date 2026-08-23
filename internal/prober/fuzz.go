package prober

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Lost-illusion69/recongo/models"
)

const (
	fuzzBodyLimit      = 8 << 10
	fuzzBaselineSlack  = 48
	defaultFuzzWorkers = 50
)

// FuzzEligible reports whether a probed web app should be directory-fuzzed.
// Live apps are those that answered 200 or 403 during the probe phase.
func FuzzEligible(status int) bool {
	return status == http.StatusOK || status == http.StatusForbidden
}

// Fuzz runs concurrent path discovery against baseURL using words (rooted paths).
// Hits are wildcard-filtered against a nonce baseline so catch-all 200/403
// virtual hosts do not flood the result set.
func Fuzz(ctx context.Context, baseURL string, words []string, opts Options, workers int) ([]models.FuzzHit, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		return nil, fmt.Errorf("prober: empty fuzz base URL")
	}
	if len(words) == 0 {
		return nil, fmt.Errorf("prober: empty fuzz wordlist")
	}
	if workers <= 0 {
		workers = defaultFuzzWorkers
	}

	opts = opts.withDefaults()
	client, err := newClient(opts)
	if err != nil {
		return nil, err
	}
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}

	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("prober: invalid fuzz base URL %q", baseURL)
	}

	baseline, err := fuzzRequest(ctx, client, opts, baseURL+"/recongo-fuzz-"+noncePath())
	if err != nil && ctx.Err() != nil {
		return nil, ctx.Err()
	}

	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	var mu sync.Mutex
	hits := make([]models.FuzzHit, 0, 32)

	for _, word := range words {
		if ctx.Err() != nil {
			break
		}
		word := word
		select {
		case <-ctx.Done():
			wg.Wait()
			return nil, ctx.Err()
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func() {
			defer func() {
				<-sem
				wg.Done()
			}()

			target := baseURL + word
			hit, reqErr := fuzzRequest(ctx, client, opts, target)
			if reqErr != nil {
				return
			}
			if !isInterestingFuzzStatus(hit.StatusCode) {
				return
			}
			if isWildcardHit(hit, baseline) {
				return
			}
			hit.Path = normalizeFuzzPath(word)
			hit.URL = target
			hit.Kind = classifyFuzzPath(hit.Path)

			mu.Lock()
			hits = append(hits, hit)
			mu.Unlock()

			if opts.Verbose {
				fmt.Fprintf(os.Stderr, "  [fuzz] %d  %s  (%s)\n", hit.StatusCode, hit.URL, hit.Kind)
			}
		}()
	}
	wg.Wait()

	sort.Slice(hits, func(i, j int) bool {
		if hits[i].Path == hits[j].Path {
			return hits[i].StatusCode < hits[j].StatusCode
		}
		return hits[i].Path < hits[j].Path
	})
	return dedupeFuzzHits(hits), nil
}

// MergeFuzzIntoEndpoints appends discovered fuzz paths onto the existing
// endpoint list, preserving uniqueness and stable sort order.
func MergeFuzzIntoEndpoints(endpoints []string, hits []models.FuzzHit) []string {
	seen := make(map[string]struct{}, len(endpoints)+len(hits))
	out := make([]string, 0, len(endpoints)+len(hits))
	for _, ep := range endpoints {
		ep = strings.TrimSpace(ep)
		if ep == "" {
			continue
		}
		if _, ok := seen[ep]; ok {
			continue
		}
		seen[ep] = struct{}{}
		out = append(out, ep)
	}
	for _, h := range hits {
		p := h.Path
		if p == "" {
			p = normalizeFuzzPath(h.URL)
		}
		if p == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

func fuzzRequest(ctx context.Context, client *http.Client, opts Options, rawURL string) (models.FuzzHit, error) {
	applyDelay(opts.Delay)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return models.FuzzHit{}, err
	}
	applyHeaders(req, opts)

	resp, err := client.Do(req)
	if err != nil {
		return models.FuzzHit{}, err
	}
	defer resp.Body.Close()

	body, err := readLimitedBody(resp.Body, fuzzBodyLimit)
	if err != nil {
		return models.FuzzHit{}, err
	}

	cl := resp.ContentLength
	if cl < 0 {
		cl = int64(len(body))
	}

	host := req.URL.Hostname()
	if shouldRetryStatus(resp.StatusCode) {
		recordRateLimit(host)
	} else {
		resetBackoff(host)
	}

	return models.FuzzHit{
		StatusCode:    resp.StatusCode,
		ContentLength: cl,
	}, nil
}

func isInterestingFuzzStatus(code int) bool {
	switch code {
	case 200, 201, 204, 301, 302, 303, 307, 308, 401, 403:
		return true
	default:
		return false
	}
}

func isWildcardHit(hit, baseline models.FuzzHit) bool {
	if baseline.StatusCode == 0 {
		return false
	}
	if hit.StatusCode != baseline.StatusCode {
		return false
	}
	delta := hit.ContentLength - baseline.ContentLength
	if delta < 0 {
		delta = -delta
	}
	return delta <= fuzzBaselineSlack
}

func normalizeFuzzPath(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	if u, err := url.Parse(s); err == nil && u.Path != "" && (u.Scheme != "" || u.Host != "") {
		s = u.Path
	}
	s = strings.ReplaceAll(s, `\`, "/")
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		s = s[:i]
	}
	if !strings.HasPrefix(s, "/") {
		s = "/" + s
	}
	cleaned := path.Clean(s)
	if cleaned == "." {
		return "/"
	}
	if strings.HasSuffix(s, "/") && cleaned != "/" {
		cleaned += "/"
	}
	return cleaned
}

func classifyFuzzPath(p string) string {
	lower := strings.ToLower(p)
	apiSignals := []string{"/api", "/graphql", "/rest", "/openapi", "/swagger", "/v1/", "/v2/", "/v3/", "/oauth"}
	for _, sig := range apiSignals {
		if strings.Contains(lower, sig) {
			return "api"
		}
	}
	base := lower
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[i+1:]
	}
	if strings.HasSuffix(lower, "/") || !strings.Contains(base, ".") {
		return "directory"
	}
	return "file"
}

func dedupeFuzzHits(hits []models.FuzzHit) []models.FuzzHit {
	if len(hits) < 2 {
		return hits
	}
	out := hits[:0]
	var prev string
	for _, h := range hits {
		if h.Path == prev {
			continue
		}
		prev = h.Path
		out = append(out, h)
	}
	return out
}

func noncePath() string {
	return fmt.Sprintf("%d-%d", os.Getpid(), time.Now().UnixNano())
}
