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
	// fuzzAbortSample is how many interesting responses are observed before a
	// uniform blocking status stops the sweep. Small enough to spare the target
	// thousands of wasted requests, large enough to ignore small samples.
	fuzzAbortSample = 120
)

// BlockedError reports that content discovery was abandoned because every
// sampled response carried one identical wall status — the signature of a WAF,
// bot-defense page, or rate limiter answering every path the same way.
type BlockedError struct {
	Status  int // HTTP status shared by every sampled response
	Sampled int // total interesting responses observed before aborting
}

func (e *BlockedError) Error() string {
	return fmt.Sprintf("prober: fuzz aborted: %d responses answered HTTP %d (WAF or rate limit)", e.Sampled, e.Status)
}

// fuzzMonitor tallies interesting response statuses during a sweep and flips
// to a stopped state once a single wall status dominates the sample window.
type fuzzMonitor struct {
	mu      sync.Mutex
	sampled map[int]int
	walled  bool
	status  int
}

func newFuzzMonitor() *fuzzMonitor { return &fuzzMonitor{sampled: make(map[int]int)} }

// observe records an interesting status and reports whether the sweep may
// continue. Diversity (two or more distinct statuses) permanently disarms the
// abort so mixed-result sites are never cut short.
func (m *fuzzMonitor) observe(status int) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.walled {
		return false
	}
	m.sampled[status]++
	if len(m.sampled) != 1 {
		return true // statuses vary: normal site, never abort
	}
	total := m.sampled[status]
	if total < fuzzAbortSample {
		return true
	}
	switch status {
	case http.StatusForbidden, http.StatusUnauthorized:
		m.walled = true
		m.status = status
		return false
	default:
		return true
	}
}

// stopped reports whether the sweep has been walled off.
func (m *fuzzMonitor) stopped() bool {
	if m == nil {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.walled
}

// err returns the sentinel error when the sweep was aborted, nil otherwise.
func (m *fuzzMonitor) err() error {
	if !m.stopped() {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	total := 0
	for _, c := range m.sampled {
		total += c
	}
	return &BlockedError{Status: m.status, Sampled: total}
}

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
	mon := newFuzzMonitor()
	hits := make([]models.FuzzHit, 0, 32)

	for _, word := range words {
		if ctx.Err() != nil {
			break
		}
		if mon.stopped() {
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
			if !mon.observe(hit.StatusCode) {
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
	if err := mon.err(); err != nil {
		return nil, err
	}

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

// ---------------------------------------------------------------------------
// Extension expansion and recursive content discovery.
// ---------------------------------------------------------------------------

// FuzzConfig controls extension expansion and optional recursive directory
// descent. Depth=1 is a single flat pass (behavioural superset of Fuzz).
type FuzzConfig struct {
	BaseURL    string
	Words      []string
	Extensions []string // optional extension variants probed for directory entries
	Opts       Options
	Workers    int
	Depth      int // maximum directory recursion depth (1 = root only)
	MaxDirs    int // cap on total directories scanned across all levels
}

func (c FuzzConfig) withDefaults() FuzzConfig {
	if c.BaseURL == "" {
		return c
	}
	c.BaseURL = strings.TrimRight(strings.TrimSpace(c.BaseURL), "/")
	if c.Depth <= 0 {
		c.Depth = 1
	}
	if c.MaxDirs <= 0 {
		c.MaxDirs = 64
	}
	if c.Workers <= 0 {
		c.Workers = defaultFuzzWorkers
	}
	return c
}

// fuzzProbe is the minimal response surface the discovery loop consumes.
type fuzzProbe struct {
	status   int
	length   int64
	location string
}

// fuzzProbeRequest issues a single GET and records status, body length, and
// any redirect Location so recursive discovery can follow directory hits.
func fuzzProbeRequest(ctx context.Context, client *http.Client, opts Options, rawURL string) (fuzzProbe, error) {
	applyDelay(opts.Delay)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return fuzzProbe{}, err
	}
	applyHeaders(req, opts)

	resp, err := client.Do(req)
	if err != nil {
		return fuzzProbe{}, err
	}
	defer resp.Body.Close()

	body, err := readLimitedBody(resp.Body, fuzzBodyLimit)
	if err != nil {
		return fuzzProbe{}, err
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

	return fuzzProbe{
		status:   resp.StatusCode,
		length:   cl,
		location: resp.Header.Get("Location"),
	}, nil
}

// ExpandExtensions grows each directory-like word by appending the supplied
// extensions to expose backup/source/dot files, e.g. /admin -> /admin.bak.
// Words whose final segment already carries a file extension are left as-is.
func ExpandExtensions(words []string, exts []string) []string {
	out := make([]string, 0, len(words)*(len(exts)+1))
	for _, w := range words {
		out = append(out, w)
		seg := strings.TrimRight(w, "/")
		if i := strings.LastIndex(seg, "/"); i >= 0 {
			seg = seg[i+1:]
		}
		if strings.Contains(seg, ".") {
			continue
		}
		base := strings.TrimRight(w, "/")
		for _, e := range exts {
			e = strings.TrimSpace(e)
			e = strings.Trim(e, ".")
			if e == "" {
				continue
			}
			out = append(out, base+"."+e)
		}
	}
	return out
}

// FuzzWithConfig runs extension-aware, optionally recursive content discovery.
func FuzzWithConfig(ctx context.Context, cfg FuzzConfig) ([]models.FuzzHit, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	cfg = cfg.withDefaults()
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("prober: empty fuzz base URL")
	}
	if len(cfg.Words) == 0 {
		return nil, fmt.Errorf("prober: empty fuzz wordlist")
	}
	parsed, err := url.Parse(cfg.BaseURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("prober: invalid fuzz base URL %q", cfg.BaseURL)
	}

	words := cfg.Words
	if len(cfg.Extensions) > 0 {
		words = ExpandExtensions(words, cfg.Extensions)
	}

	opts := cfg.Opts.withDefaults()
	client, err := newClient(opts)
	if err != nil {
		return nil, err
	}
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}

	// Root the crawl at scheme://host[/path] with a trailing slash.
	origin := parsed.Scheme + "://" + parsed.Host
	pth := strings.Trim(parsed.Path, "/")
	rootURL := origin + "/"
	rootRel := ""
	if pth != "" {
		rootURL += pth + "/"
		rootRel = pth + "/"
	}
	recursive := cfg.Depth > 1

	var all []models.FuzzHit
	visited := make(map[string]struct{})
	visited[rootRel] = struct{}{}
	frontier := []string{rootURL}
	dirsUsed := 1

	for depth := 1; depth <= cfg.Depth && len(frontier) > 0; depth++ {
		var next []string
		for _, dirURL := range frontier {
			hits, children, berr := runFuzzBatch(ctx, client, opts, dirURL, origin, words, recursive, cfg.Workers)
			if berr != nil {
				return all, berr
			}
			for _, h := range hits {
				all = append(all, h)
			}
			for _, child := range children {
				rel := relPathOf(child, origin)
				if rel == "" {
					continue
				}
				if _, ok := visited[rel]; ok {
					continue
				}
				if dirsUsed >= cfg.MaxDirs {
					continue
				}
				visited[rel] = struct{}{}
				dirsUsed++
				next = append(next, child)
			}
		}
		frontier = next
	}

	sort.Slice(all, func(i, j int) bool {
		if all[i].Path == all[j].Path {
			return all[i].StatusCode < all[j].StatusCode
		}
		return all[i].Path < all[j].Path
	})
	return dedupeFuzzHits(all), nil
}

// runFuzzBatch fuzzes one directory URL, returning any hits and the child
// directories discovered beneath it.
func runFuzzBatch(ctx context.Context, client *http.Client, opts Options, dirURL, origin string, words []string, recursive bool, workers int) ([]models.FuzzHit, []string, error) {
	dirBase := strings.TrimRight(dirURL, "/")
	baseline, _ := fuzzProbeRequest(ctx, client, opts, dirBase+"/recongo-fuzz-"+noncePath())

	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	var mu sync.Mutex
	mon := newFuzzMonitor()
	var hits []models.FuzzHit
	var children []string

	for _, word := range words {
		if ctx.Err() != nil {
			wg.Wait()
			return hits, children, ctx.Err()
		}
		if mon.stopped() {
			break
		}
		select {
		case <-ctx.Done():
			wg.Wait()
			return hits, children, ctx.Err()
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func(word string) {
			defer func() { <-sem; wg.Done() }()
			target := dirBase + word
			probe, reqErr := fuzzProbeRequest(ctx, client, opts, target)
			if reqErr != nil {
				return
			}
			if !isInterestingFuzzStatus(probe.status) {
				return
			}
			if !mon.observe(probe.status) {
				return
			}
			if isWildcardProbe(probe, baseline) {
				return
			}
			normalized := normalizeFuzzPath(target)
			hit := models.FuzzHit{
				Path:          normalized,
				URL:           target,
				StatusCode:    probe.status,
				ContentLength: probe.length,
				Kind:          classifyFuzzPath(normalized),
			}
			mu.Lock()
			hits = append(hits, hit)
			if recursive {
				if child := suggestedChildDir(dirURL, origin, target, probe); child != "" {
					children = append(children, child)
				}
			}
			mu.Unlock()
			if opts.Verbose {
				fmt.Fprintf(os.Stderr, "  [fuzz] %d  %s  (%s)\n", hit.StatusCode, hit.URL, hit.Kind)
			}
		}(word)
	}
	wg.Wait()
	return hits, children, mon.err()
}

// isRedirectStatus reports whether a status code is a redirect worth following
// during recursive content discovery.
func isRedirectStatus(code int) bool {
	switch code {
	case http.StatusMovedPermanently,
		http.StatusFound,
		http.StatusSeeOther,
		http.StatusTemporaryRedirect,
		http.StatusPermanentRedirect:
		return true
	default:
		return false
	}
}

// suggestedChildDir detects endpoints discovered under dirURL that deserve a
// recursive pass: trailing-slash directory entries (2xx/3xx) and same-origin
// redirects that land on a directory path.
func suggestedChildDir(dirURL, origin, target string, probe fuzzProbe) string {
	var candidate string
	if strings.HasSuffix(target, "/") && probe.status >= 200 && probe.status < 400 {
		candidate = target
	} else if isRedirectStatus(probe.status) {
		loc := strings.TrimSpace(probe.location)
		if strings.HasPrefix(loc, "/") {
			if u, err := url.Parse(loc); err == nil {
				candidate = origin + u.Path
			}
		}
	}
	return containedChildDir(candidate, dirURL)
}

// containedChildDir accepts a child only when it is strictly below the parent
// path (guarding against loops and sibling drift) and carries a trailing slash.
func containedChildDir(child, parent string) string {
	child = strings.TrimRight(child, "/") + "/"
	parent = strings.TrimRight(parent, "/") + "/"
	if child == parent {
		return ""
	}
	if !strings.HasPrefix(child, parent) {
		return ""
	}
	return child
}

// relPathOf reduces an absolute child URL to a root-relative key used by the
// visited set, so equivalent paths are never rescanned.
func relPathOf(child, origin string) string {
	rest := strings.TrimPrefix(child, origin)
	return strings.Trim(rest, "/")
}

// FuzzEligibleWith401 reports whether a probed app is worth fuzzing, optionally
// accepting HTTP 401 (auth-gated) apps whose responses still vary by resource.
func FuzzEligibleWith401(status int, allowUnauthorized bool) bool {
	if status == http.StatusOK || status == http.StatusForbidden {
		return true
	}
	return allowUnauthorized && status == http.StatusUnauthorized
}

// isWildcardProbe drops responses that match the directory catch-all baseline.
func isWildcardProbe(hit, base fuzzProbe) bool {
	if base.status == 0 {
		return false
	}
	if hit.status != base.status {
		return false
	}
	delta := hit.length - base.length
	if delta < 0 {
		delta = -delta
	}
	return delta <= fuzzBaselineSlack
}
