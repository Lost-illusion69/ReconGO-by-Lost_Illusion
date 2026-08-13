// Package origin discovers non-proxied mail/origin IP candidates and CDN metadata.
package origin

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/Lost-illusion69/recongo/models"
)

var (
	spfIP4Re  = regexp.MustCompile(`(?i)ip4:([0-9./]+)`)
	spfIP6Re  = regexp.MustCompile(`(?i)ip6:([0-9a-f:/]+)`)
	ipv4Re    = regexp.MustCompile(`^\d{1,3}(\.\d{1,3}){3}$`)
	cnameSink = map[string]struct{}{
		"github.io": {}, "herokudns.com": {}, "azurewebsites.net": {},
		"cloudfront.net": {}, "s3.amazonaws.com": {}, "shopify.com": {},
	}
)

// Findings holds domain-level origin intelligence from DNS records.
type Findings struct {
	MailHostnames []string
	SPFRanges     []string
	CandidateIPs  []string
}

// Discover parses MX and SPF records for a root domain.
func Discover(ctx context.Context, domain string, r *net.Resolver) (*Findings, error) {
	if r == nil {
		r = net.DefaultResolver
	}
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return nil, fmt.Errorf("origin: empty domain")
	}

	findings := &Findings{}
	ipSeen := make(map[string]struct{})

	addIP := func(ip string) {
		ip = strings.TrimSpace(ip)
		if ip == "" || !looksLikeIP(ip) {
			return
		}
		if _, ok := ipSeen[ip]; ok {
			return
		}
		ipSeen[ip] = struct{}{}
		findings.CandidateIPs = append(findings.CandidateIPs, ip)
	}

	mx, err := r.LookupMX(ctx, domain)
	if err == nil {
		for _, rec := range mx {
			host := strings.TrimSuffix(rec.Host, ".")
			findings.MailHostnames = append(findings.MailHostnames, host)
			ips, err := r.LookupHost(ctx, host)
			if err == nil {
				for _, ip := range ips {
					addIP(ip)
				}
			}
		}
	}

	txts, err := r.LookupTXT(ctx, domain)
	if err == nil {
		for _, txt := range txts {
			if !strings.HasPrefix(strings.ToLower(txt), "v=spf1") {
				continue
			}
			for _, m := range spfIP4Re.FindAllStringSubmatch(txt, -1) {
				findings.SPFRanges = append(findings.SPFRanges, "ip4:"+m[1])
				if strings.Contains(m[1], "/") {
					continue
				}
				addIP(m[1])
			}
			for _, m := range spfIP6Re.FindAllStringSubmatch(txt, -1) {
				findings.SPFRanges = append(findings.SPFRanges, "ip6:"+m[1])
			}
		}
	}

	sort.Strings(findings.MailHostnames)
	sort.Strings(findings.SPFRanges)
	sort.Strings(findings.CandidateIPs)
	return findings, nil
}

// DetectCDN inspects response headers and server banner for CDN signals.
func DetectCDN(h http.Header, server string) (proxied bool, provider string) {
	checks := []struct {
		header, value, name string
	}{
		{"CF-RAY", "", "Cloudflare"},
		{"Server", "cloudflare", "Cloudflare"},
		{"X-Amz-Cf-Id", "", "AWS CloudFront"},
		{"X-Amz-Cf-Pop", "", "AWS CloudFront"},
		{"X-Akamai-Transformed", "", "Akamai"},
		{"Server", "AkamaiGHost", "Akamai"},
		{"X-Cache", "cloudfront", "AWS CloudFront"},
	}
	for _, c := range checks {
		v := h.Get(c.header)
		if v == "" {
			continue
		}
		if c.value == "" || strings.Contains(strings.ToLower(v), strings.ToLower(c.value)) {
			return true, c.name
		}
	}
	if s := strings.ToLower(server); s != "" {
		switch {
		case strings.Contains(s, "cloudflare"):
			return true, "Cloudflare"
		case strings.Contains(s, "cloudfront"):
			return true, "AWS CloudFront"
		case strings.Contains(s, "akamai"):
			return true, "Akamai"
		}
	}
	return false, ""
}

// FaviconFetcher returns the MMH3 favicon hash for a host/IP target.
type FaviconFetcher func(ctx context.Context, host string) (int32, error)

// CorrelateByFavicon flags candidate IPs whose favicon hash matches the CDN-fronted host.
func CorrelateByFavicon(ctx context.Context, candidates []string, targetMMH3 int32, fetch FaviconFetcher) []string {
	if targetMMH3 == 0 || len(candidates) == 0 || fetch == nil {
		return nil
	}
	var (
		mu   sync.Mutex
		out  []string
		seen = make(map[string]struct{})
		wg   sync.WaitGroup
		sem  = make(chan struct{}, 4)
	)
	for _, ip := range candidates {
		ip := ip
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			hash, err := fetch(ctx, ip)
			if err != nil || hash != targetMMH3 {
				return
			}
			mu.Lock()
			if _, ok := seen[ip]; !ok {
				seen[ip] = struct{}{}
				out = append(out, ip)
			}
			mu.Unlock()
		}()
	}
	wg.Wait()
	sort.Strings(out)
	return out
}

// EnrichResult attaches CDN and origin correlation data to a probe result.
func EnrichResult(r *models.Result, respHeader http.Header, domainFindings *Findings, correlate bool, fetch FaviconFetcher) {
	if r == nil {
		return
	}
	proxied, provider := DetectCDN(respHeader, r.Server)
	r.IsCDNProxied = proxied
	r.CDNProvider = provider

	if !correlate || domainFindings == nil || len(domainFindings.CandidateIPs) == 0 {
		if r.PotentialOriginIPs == nil {
			r.PotentialOriginIPs = []string{}
		}
		return
	}

	ctx := context.Background()
	matches := CorrelateByFavicon(ctx, domainFindings.CandidateIPs, r.FaviconMMH3, fetch)
	if len(matches) == 0 {
		// Fall back to non-CDN mail/SPF candidates when favicon correlation unavailable.
		matches = append([]string{}, domainFindings.CandidateIPs...)
	}
	r.PotentialOriginIPs = matches
}

// TakeoverRisk checks CNAME targets against known dangling-service fingerprints.
func TakeoverRisk(ctx context.Context, host string, r *net.Resolver) (bool, string) {
	if r == nil {
		r = net.DefaultResolver
	}
	cname, err := r.LookupCNAME(ctx, host)
	if err != nil || cname == "" {
		return false, ""
	}
	target := strings.ToLower(strings.TrimSuffix(cname, "."))
	if cnameMatchesSink(target) {
		return true, target
	}
	return false, target
}

func cnameMatchesSink(target string) bool {
	for sink := range cnameSink {
		if strings.Contains(target, sink) {
			return true
		}
	}
	return false
}

func looksLikeIP(s string) bool {
	return ipv4Re.MatchString(s) || strings.Contains(s, ":")
}
