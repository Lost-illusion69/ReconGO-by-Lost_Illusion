// Package models defines shared data types for the ReconGo pipeline.
package models

import "time"

// Result holds the outcome of a successful HTTP probe against a host.
type Result struct {
	Host          string        `json:"host"`
	IPs           []string      `json:"ips"`
	URL           string        `json:"url"`
	StatusCode    int           `json:"status_code"`
	Title         string        `json:"title"`
	Server        string        `json:"server"`
	ContentLength int64         `json:"content_length"`
	ResponseTime  time.Duration `json:"response_time_ns"`
	FaviconMMH3   int32         `json:"favicon_mmh3,omitempty" csv:"favicon_mmh3"`
	BodyMMH3      int32         `json:"body_mmh3,omitempty" csv:"body_mmh3"`
	ClusterTag    string        `json:"cluster_tag,omitempty" csv:"cluster_tag"`
	Endpoints     []string      `json:"endpoints" csv:"endpoints"`

	// Content discovery hits from the optional -fuzz phase.
	FuzzResults []FuzzHit `json:"fuzz_results"`

	// Archive intelligence (Wayback / OTX).
	HistoricalURLs   []string `json:"historical_urls"`
	DiscoveredParams []string `json:"discovered_params"`

	// CDN bypass / origin correlation.
	IsCDNProxied       bool     `json:"is_cdn_proxied"`
	CDNProvider        string   `json:"cdn_provider,omitempty"`
	PotentialOriginIPs []string `json:"potential_origin_ips"`

	// Takeover assessment. Confirmed=true means both the DNS signal (CNAME or
	// A-record) and a live fingerprint check on the response body agreed;
	// Confirmed=false with Risk=true means the DNS signal fired but couldn't
	// be (or wasn't) verified against the live page — treat as a lead, not a
	// report-ready finding.
	TakeoverRisk      bool   `json:"takeover_risk,omitempty"`
	TakeoverService   string `json:"takeover_service,omitempty"`
	TakeoverCNAME     string `json:"takeover_cname,omitempty"`
	TakeoverIP        string `json:"takeover_ip,omitempty"`
	TakeoverConfirmed bool   `json:"takeover_confirmed,omitempty"`

	// Exposed credential material found in HTML/JS bodies (optional -secrets).
	Secrets []SecretFinding `json:"secrets"`

	// Cross-origin misconfigurations found by reflecting attacker origins
	// (optional -cors).
	CORS []CORSFinding `json:"cors"`
}

// CORSFinding is a single confirmed CORS misconfiguration on a probed host.
type CORSFinding struct {
	SentOrigin       string `json:"sent_origin"`
	Reflected        string `json:"reflected_origin"`
	AllowCredentials bool   `json:"allow_credentials"`
	Severity         string `json:"severity"`
	Note             string `json:"note,omitempty"`
}

// SecretFinding is a redacted credential candidate detected in client code.
type SecretFinding struct {
	Kind       string `json:"kind"`
	Confidence string `json:"confidence"`
	Value      string `json:"value"`
	Source     string `json:"source"`
	Context    string `json:"context,omitempty"`
}

// FuzzHit is a single directory/file/API path confirmed during content discovery.
type FuzzHit struct {
	Path          string `json:"path"`
	URL           string `json:"url"`
	StatusCode    int    `json:"status_code"`
	ContentLength int64  `json:"content_length"`
	Kind          string `json:"kind"`
}
