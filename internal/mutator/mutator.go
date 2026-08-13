// Package mutator generates cross-environment and cross-region subdomain
// mutations from discovered hosts.
package mutator

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
)

var (
	envTags = map[string]struct{}{
		"dev": {}, "stage": {}, "prod": {}, "test": {}, "uat": {}, "qa": {},
	}
	funcTags = map[string]struct{}{
		"api": {}, "app": {}, "admin": {}, "auth": {}, "portal": {}, "db": {},
	}
	regionTags = []string{"us-east", "us-west", "eu-central", "asia"}
)

// Config controls mutation generation limits.
type Config struct {
	// MaxMutations caps total emitted candidates (default 500).
	MaxMutations int
	// RootDomain is the scan target (e.g. example.com).
	RootDomain string
}

func (c Config) withDefaults() Config {
	if c.MaxMutations <= 0 {
		c.MaxMutations = 500
	}
	return c
}

// Engine generates subdomain mutations from discovered hosts.
type Engine struct {
	cfg Config

	visited sync.Map // host -> struct{}
	emitted atomic.Int64

	envsSeen    sync.Map
	regionsSeen sync.Map
	funcsSeen   sync.Map
}

// New constructs a mutation engine.
func New(cfg Config) *Engine {
	return &Engine{cfg: cfg.withDefaults()}
}

// MarkSeen records a host so it will not be emitted or re-mutated.
func (e *Engine) MarkSeen(host string) {
	host = strings.ToLower(strings.TrimSpace(host))
	if host != "" {
		e.visited.Store(host, struct{}{})
	}
}

// Seen reports whether host was already visited.
func (e *Engine) Seen(host string) bool {
	_, ok := e.visited.Load(strings.ToLower(strings.TrimSpace(host)))
	return ok
}

// Emit sends host to out if under cap and not visited. Returns true when sent.
func (e *Engine) Emit(ctx context.Context, host string, out chan<- string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" || e.Seen(host) {
		return false
	}
	if e.emitted.Load() >= int64(e.cfg.MaxMutations) {
		return false
	}

	e.visited.Store(host, struct{}{})
	e.emitted.Add(1)

	select {
	case out <- host:
		return true
	case <-ctx.Done():
		return false
	}
}

// Mutate parses host and emits cross-environment / cross-region variants.
func (e *Engine) Mutate(ctx context.Context, host string, out chan<- string) {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return
	}
	e.MarkSeen(host)

	parsed, ok := parseHost(host, e.cfg.RootDomain)
	if !ok {
		return
	}
	e.recordTags(parsed)

	envPool := e.tagPool(&e.envsSeen, envTags)
	regionPool := e.regionPool()

	currentEnv := parsed.env
	currentRegion := parsed.region
	currentFunc := parsed.functional

	// Cross-mutate environments (keep region + functional fixed).
	for _, env := range envPool {
		if env == currentEnv {
			continue
		}
		if e.emitted.Load() >= int64(e.cfg.MaxMutations) {
			return
		}
		candidate := parsed.rebuild(currentFunc, env, currentRegion)
		e.Emit(ctx, candidate, out)
	}

	// Cross-mutate regions (keep env + functional fixed).
	for _, region := range regionPool {
		if region == currentRegion {
			continue
		}
		if e.emitted.Load() >= int64(e.cfg.MaxMutations) {
			return
		}
		candidate := parsed.rebuild(currentFunc, currentEnv, region)
		e.Emit(ctx, candidate, out)
	}
}

func (e *Engine) recordTags(p parsedHost) {
	if p.env != "" {
		e.envsSeen.Store(p.env, struct{}{})
	}
	if p.region != "" {
		e.regionsSeen.Store(p.region, struct{}{})
	}
	if p.functional != "" {
		e.funcsSeen.Store(p.functional, struct{}{})
	}
}

func (e *Engine) tagPool(seen *sync.Map, defaults map[string]struct{}) []string {
	out := make(map[string]struct{})
	for k := range defaults {
		out[k] = struct{}{}
	}
	seen.Range(func(k, _ any) bool {
		if s, ok := k.(string); ok {
			out[s] = struct{}{}
		}
		return true
	})
	list := make([]string, 0, len(out))
	for k := range out {
		list = append(list, k)
	}
	return list
}

func (e *Engine) regionPool() []string {
	out := make(map[string]struct{})
	for _, r := range regionTags {
		out[r] = struct{}{}
	}
	e.regionsSeen.Range(func(k, _ any) bool {
		if s, ok := k.(string); ok {
			out[s] = struct{}{}
		}
		return true
	})
	list := make([]string, 0, len(out))
	for k := range out {
		list = append(list, k)
	}
	return list
}

// Emitted returns the number of mutation candidates sent so far.
func (e *Engine) Emitted() int64 {
	return e.emitted.Load()
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

type parsedHost struct {
	rootDomain string
	prefix     string
	tokens     []string
	functional string
	env        string
	region     string
}

func parseHost(host, rootDomain string) (parsedHost, bool) {
	rootDomain = strings.ToLower(strings.TrimSpace(rootDomain))
	host = strings.ToLower(strings.TrimSpace(host))
	if rootDomain == "" || host == "" {
		return parsedHost{}, false
	}

	suffix := "." + rootDomain
	if !strings.HasSuffix(host, suffix) && host != rootDomain {
		// Allow hosts that end with root domain or equal it.
		if strings.HasSuffix(host, rootDomain) {
			suffix = rootDomain
		} else {
			return parsedHost{}, false
		}
	}

	var prefix string
	switch {
	case host == rootDomain:
		prefix = ""
	case strings.HasSuffix(host, "."+rootDomain):
		prefix = strings.TrimSuffix(host, "."+rootDomain)
	default:
		return parsedHost{}, false
	}

	tokens := tokenize(prefix)
	if len(tokens) == 0 {
		return parsedHost{}, false
	}

	p := parsedHost{
		rootDomain: rootDomain,
		prefix:     prefix,
		tokens:     tokens,
	}

	p.functional, p.env, p.region = classifyTokens(tokens)
	return p, true
}

func tokenize(prefix string) []string {
	if prefix == "" {
		return nil
	}
	replacer := strings.NewReplacer(".", "-", "_", "-")
	normalized := replacer.Replace(prefix)
	parts := strings.Split(normalized, "-")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func classifyTokens(tokens []string) (functional, env, region string) {
	used := make([]bool, len(tokens))

	// Multi-token regions first (e.g. us-east).
	for _, r := range regionTags {
		rParts := strings.Split(r, "-")
		if idx := findSubsequence(tokens, rParts); idx >= 0 {
			region = r
			for i := 0; i < len(rParts); i++ {
				used[idx+i] = true
			}
		}
	}

	for i, tok := range tokens {
		if used[i] {
			continue
		}
		if _, ok := envTags[tok]; ok && env == "" {
			env = tok
			used[i] = true
			continue
		}
		if _, ok := funcTags[tok]; ok && functional == "" {
			functional = tok
			used[i] = true
		}
	}
	return functional, env, region
}

func findSubsequence(tokens, pattern []string) int {
	if len(pattern) == 0 || len(tokens) < len(pattern) {
		return -1
	}
outer:
	for i := 0; i <= len(tokens)-len(pattern); i++ {
		for j := range pattern {
			if tokens[i+j] != pattern[j] {
				continue outer
			}
		}
		return i
	}
	return -1
}

func (p parsedHost) rebuild(functional, env, region string) string {
	tokens := append([]string(nil), p.tokens...)

	// Clear previously classified tag tokens.
	clean := make([]string, 0, len(tokens))
	used := make([]bool, len(tokens))
	if p.region != "" {
		rParts := strings.Split(p.region, "-")
		if idx := findSubsequence(tokens, rParts); idx >= 0 {
			for i := range rParts {
				used[idx+i] = true
			}
		}
	}
	for i, tok := range tokens {
		if used[i] {
			continue
		}
		if tok == p.env || tok == p.functional {
			continue
		}
		clean = append(clean, tok)
	}

	parts := make([]string, 0, len(clean)+3)
	if functional != "" {
		parts = append(parts, functional)
	}
	parts = append(parts, clean...)
	if env != "" {
		parts = append(parts, env)
	}
	if region != "" {
		parts = append(parts, strings.Split(region, "-")...)
	}

	prefix := strings.Join(parts, "-")
	if prefix == "" {
		return p.rootDomain
	}
	return prefix + "." + p.rootDomain
}

// Run drains discovered hosts and streams mutation candidates to out.
func (e *Engine) Run(ctx context.Context, discovered <-chan string, out chan<- string) {
	for {
		select {
		case <-ctx.Done():
			return
		case host, ok := <-discovered:
			if !ok {
				return
			}
			e.Mutate(ctx, host, out)
		}
	}
}
