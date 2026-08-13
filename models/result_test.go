package models

import (
	"encoding/json"
	"testing"
	"time"
)

func TestResultJSONRoundTrip(t *testing.T) {
	r := Result{
		Host:               "api.example.com",
		IPs:                []string{"1.2.3.4"},
		URL:                "https://api.example.com",
		StatusCode:         200,
		Title:              "Portal",
		Server:             "nginx",
		ContentLength:      512,
		ResponseTime:       42 * time.Millisecond,
		FaviconMMH3:        111,
		BodyMMH3:           222,
		ClusterTag:         "body-1",
		Endpoints:          []string{"/api/v1"},
		HistoricalURLs:     []string{"/old/path"},
		DiscoveredParams:   []string{"token"},
		IsCDNProxied:       true,
		CDNProvider:        "Cloudflare",
		PotentialOriginIPs: []string{"203.0.113.1"},
		TakeoverRisk:       false,
	}

	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}

	var decoded Result
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Host != r.Host {
		t.Errorf("host = %q", decoded.Host)
	}
	if len(decoded.Endpoints) != 1 || decoded.Endpoints[0] != "/api/v1" {
		t.Errorf("endpoints = %v", decoded.Endpoints)
	}
	if !decoded.IsCDNProxied || decoded.CDNProvider != "Cloudflare" {
		t.Errorf("cdn = %v %q", decoded.IsCDNProxied, decoded.CDNProvider)
	}
	if len(decoded.HistoricalURLs) != 1 {
		t.Errorf("historical_urls = %v", decoded.HistoricalURLs)
	}
}

func TestResultEmptySlicesJSON(t *testing.T) {
	r := Result{Host: "x.example.com", Endpoints: []string{}}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(data) {
		t.Fatal("invalid json")
	}
	var m map[string]any
	_ = json.Unmarshal(data, &m)
	if _, ok := m["endpoints"]; !ok {
		t.Error("endpoints key should be present")
	}
}
