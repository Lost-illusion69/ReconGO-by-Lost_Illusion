package prober

import (
	"regexp"
	"sort"
	"strings"
)

var (
	apiRouteRe  = regexp.MustCompile(`/api/v[0-9]+/[a-zA-Z0-9_/-]+`)
	graphqlRe   = regexp.MustCompile(`/graphql`)
	authRouteRe = regexp.MustCompile(`/auth/[a-zA-Z0-9_/-]+`)
	jsRefRe     = regexp.MustCompile(`(?is)(?:src|href)=["']([^"']+\.js(?:\?[^"']*)?)["']`)
)

// MineEndpoints extracts API routes from HTML/JS response bodies.
func MineEndpoints(body []byte) []string {
	text := string(body)
	seen := make(map[string]struct{})
	add := func(route string) {
		route = strings.TrimSpace(route)
		if route == "" || len(route) < 2 {
			return
		}
		if !strings.HasPrefix(route, "/") {
			return
		}
		seen[route] = struct{}{}
	}

	for _, m := range apiRouteRe.FindAllString(text, -1) {
		add(m)
	}
	for _, m := range graphqlRe.FindAllString(text, -1) {
		add(m)
	}
	for _, m := range authRouteRe.FindAllString(text, -1) {
		add(m)
	}

	// Also scan quoted paths inside discovered .js references (same-body mining).
	for _, ref := range jsRefRe.FindAllStringSubmatch(text, -1) {
		if len(ref) < 2 {
			continue
		}
		mineFromSnippet(ref[1], add)
	}
	mineFromSnippet(text, add)

	out := make([]string, 0, len(seen))
	for r := range seen {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}

func mineFromSnippet(snippet string, add func(string)) {
	for _, m := range apiRouteRe.FindAllString(snippet, -1) {
		add(m)
	}
	for _, m := range graphqlRe.FindAllString(snippet, -1) {
		add(m)
	}
	for _, m := range authRouteRe.FindAllString(snippet, -1) {
		add(m)
	}
}
