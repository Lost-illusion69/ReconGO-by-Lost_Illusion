package prober

import (
	"regexp"
	"sort"
	"strings"
)

var (
	// HTML / inline script src attributes.
	jsRefRe = regexp.MustCompile(`(?i)(?:src|href)\s*=\s*["']([^"']+\.js[^"']*)["']`)

	// import("...") and from "..." patterns in bundles / HTML.
	jsImportRe = regexp.MustCompile(`(?i)(?:import\s*\(\s*["']([^"']+)["']|from\s+["']([^"']+)["'])`)

	apiPathRe = regexp.MustCompile(`(?i)(?:["'` + "`" + `]|^|\s)(/(?:api|v[0-9]+|graphql|auth|oauth|rest|services?|internal|public|private|admin|user|users|account|accounts|login|logout|register|token|session|webhook|webhooks|callback|callbacks|health|status|metrics|swagger|docs|openapi)(?:/[a-zA-Z0-9_\-./{}:?&=%]+)?)`)

	// Standalone REST-ish paths often embedded in JS strings.
	restPathRe = regexp.MustCompile(`(?i)["'` + "`" + `](/[a-zA-Z0-9_\-]+(?:/[a-zA-Z0-9_\-{}]+){1,6})["'` + "`" + `]`)

	graphqlRe = regexp.MustCompile(`(?i)(?:["'` + "`" + `]|^|\s)(/graphql(?:/[a-zA-Z0-9_\-./]+)?)`)
)

// MineEndpoints extracts likely API routes from HTML/JS response bodies.
func MineEndpoints(bodies ...string) []string {
	seen := make(map[string]struct{})
	var out []string

	add := func(raw string) {
		p := normalizeEndpointPath(raw)
		if p == "" {
			return
		}
		if _, ok := seen[p]; ok {
			return
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}

	for _, body := range bodies {
		if body == "" {
			continue
		}
		for _, m := range apiPathRe.FindAllStringSubmatch(body, -1) {
			if len(m) > 1 {
				add(m[1])
			}
		}
		for _, m := range graphqlRe.FindAllStringSubmatch(body, -1) {
			if len(m) > 1 {
				add(m[1])
			}
		}
		for _, m := range restPathRe.FindAllStringSubmatch(body, -1) {
			if len(m) > 1 {
				add(m[1])
			}
		}
	}

	sort.Strings(out)
	return out
}

func normalizeEndpointPath(raw string) string {
	p := strings.TrimSpace(raw)
	p = strings.Trim(p, `"'`+"`")
	p = strings.Split(p, "?")[0]
	p = strings.Split(p, "#")[0]
	if !strings.HasPrefix(p, "/") {
		return ""
	}
	if len(p) < 2 || len(p) > 256 {
		return ""
	}
	lower := strings.ToLower(p)

	// Skip static assets and obvious non-API paths.
	staticExt := []string{".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".css", ".woff", ".woff2", ".ttf", ".map", ".webp"}
	for _, ext := range staticExt {
		if strings.HasSuffix(lower, ext) {
			return ""
		}
	}
	if strings.Contains(lower, "/node_modules/") {
		return ""
	}

	// Require API-ish signal unless path has enough depth.
	apiSignals := []string{"/api", "/graphql", "/auth", "/oauth", "/rest", "/service", "/internal", "/webhook", "/swagger", "/openapi", "/v1", "/v2", "/v3", "/login", "/token", "/user", "/admin"}
	hasSignal := false
	for _, sig := range apiSignals {
		if strings.Contains(lower, sig) {
			hasSignal = true
			break
		}
	}
	if !hasSignal && strings.Count(p, "/") < 3 {
		return ""
	}

	return p
}
