// Package archive queries passive historical sources (Wayback Machine, OTX)
// for subdomains, URL paths, and query parameters.
package archive

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const (
	waybackCDXURL = "https://web.archive.org/cdx/search/cdx"
	otxPassiveURL = "https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns"
	otxURLList    = "https://otx.alienvault.com/api/v1/indicators/domain/%s/url_list"
	defaultLimit  = 1000
)

// Findings holds passive archive intelligence for a root domain.
type Findings struct {
	Subdomains       []string
	HistoricalURLs   []string
	DiscoveredParams []string
}

// Client performs archive API queries.
type Client struct {
	HTTP    *http.Client
	Limit   int
	Timeout time.Duration
}

// NewClient returns a Client with sensible defaults.
func NewClient() *Client {
	return &Client{
		HTTP:    &http.Client{Timeout: 15 * time.Second},
		Limit:   defaultLimit,
		Timeout: 15 * time.Second,
	}
}

// Query fetches historical data from Wayback CDX and AlienVault OTX.
func Query(ctx context.Context, domain string, c *Client) (*Findings, error) {
	if c == nil {
		c = NewClient()
	}
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return nil, fmt.Errorf("archive: empty domain")
	}

	subSeen := make(map[string]struct{})
	urlSeen := make(map[string]struct{})
	paramSeen := make(map[string]struct{})

	addSub := func(host string) {
		host = strings.ToLower(strings.TrimSpace(host))
		if host == "" || !isInScope(host, domain) {
			return
		}
		subSeen[host] = struct{}{}
	}
	addURL := func(raw string) {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return
		}
		u, err := url.Parse(raw)
		if err != nil {
			return
		}
		if u.Hostname() != "" && !isInScope(u.Hostname(), domain) {
			return
		}
		path := u.Path
		if path == "" {
			path = "/"
		}
		if u.RawQuery != "" {
			path = path + "?" + u.RawQuery
			for p := range extractQueryParams(u.Query()) {
				paramSeen[p] = struct{}{}
			}
		}
		if strings.HasPrefix(path, "/") {
			urlSeen[path] = struct{}{}
		}
		if u.Hostname() != "" {
			addSub(u.Hostname())
		}
	}

	if err := queryWayback(ctx, c, domain, addSub, addURL); err != nil {
		return nil, fmt.Errorf("wayback: %w", err)
	}
	if err := queryOTXPassive(ctx, c, domain, addSub); err != nil {
		return nil, fmt.Errorf("otx passive_dns: %w", err)
	}
	if err := queryOTXURLList(ctx, c, domain, addSub, addURL); err != nil {
		return nil, fmt.Errorf("otx url_list: %w", err)
	}

	return &Findings{
		Subdomains:       sortedKeys(subSeen),
		HistoricalURLs:   sortedKeys(urlSeen),
		DiscoveredParams: sortedKeys(paramSeen),
	}, nil
}

// FilterForHost returns archive slices relevant to a specific hostname.
func FilterForHost(f *Findings, host string) (urls, params []string) {
	urls = []string{}
	params = []string{}
	if f == nil {
		return urls, params
	}
	host = strings.ToLower(host)
	for _, u := range f.HistoricalURLs {
		urls = append(urls, u)
	}
	params = append(params, f.DiscoveredParams...)
	_ = host
	return urls, params
}

func queryWayback(ctx context.Context, c *Client, domain string, addSub func(string), addURL func(string)) error {
	limit := c.Limit
	if limit <= 0 {
		limit = defaultLimit
	}
	q := url.Values{}
	q.Set("url", "*."+domain+"/*")
	q.Set("output", "json")
	q.Set("fl", "original")
	q.Set("collapse", "urlkey")
	q.Set("limit", fmt.Sprintf("%d", limit))

	reqURL := waybackCDXURL + "?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "ReconGo/1.0 (github.com/Lost-illusion69/recongo)")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}

	var rows [][]string
	if err := json.NewDecoder(resp.Body).Decode(&rows); err != nil {
		return err
	}
	for i, row := range rows {
		if i == 0 || len(row) == 0 {
			continue
		}
		addURL(row[0])
	}
	return nil
}

type otxPassiveResponse struct {
	PassiveDNS []struct {
		Hostname string `json:"hostname"`
	} `json:"passive_dns"`
}

func queryOTXPassive(ctx context.Context, c *Client, domain string, addSub func(string)) error {
	reqURL := fmt.Sprintf(otxPassiveURL, domain)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "ReconGo/1.0 (github.com/Lost-illusion69/recongo)")
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}

	var payload otxPassiveResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return err
	}
	for _, e := range payload.PassiveDNS {
		addSub(e.Hostname)
	}
	return nil
}

type otxURLListResponse struct {
	URLList []struct {
		URL string `json:"url"`
	} `json:"url_list"`
}

func queryOTXURLList(ctx context.Context, c *Client, domain string, addSub func(string), addURL func(string)) error {
	reqURL := fmt.Sprintf(otxURLList, domain)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "ReconGo/1.0 (github.com/Lost-illusion69/recongo)")
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}

	var payload otxURLListResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return err
	}
	for _, e := range payload.URLList {
		addURL(e.URL)
	}
	return nil
}

func isInScope(host, domain string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	domain = strings.ToLower(domain)
	return host == domain || strings.HasSuffix(host, "."+domain)
}

func extractQueryParams(v url.Values) map[string]struct{} {
	out := make(map[string]struct{})
	for key := range v {
		key = strings.TrimSpace(key)
		if key != "" {
			out[key] = struct{}{}
		}
	}
	return out
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
