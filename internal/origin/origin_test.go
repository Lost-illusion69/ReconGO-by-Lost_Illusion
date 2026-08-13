package origin

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/Lost-illusion69/recongo/models"
)

func TestDetectCDN(t *testing.T) {
	h := http.Header{}
	h.Set("CF-RAY", "abc123")
	proxied, provider := DetectCDN(h, "")
	if !proxied || provider != "Cloudflare" {
		t.Errorf("DetectCDN() = %v, %q", proxied, provider)
	}

	h2 := http.Header{}
	proxied, provider = DetectCDN(h2, "AkamaiGHost/1.0")
	if !proxied || provider != "Akamai" {
		t.Errorf("server banner detection failed: %v %q", proxied, provider)
	}
}

func TestCorrelateByFavicon(t *testing.T) {
	fetch := func(ctx context.Context, host string) (int32, error) {
		if host == "1.2.3.4" {
			return 42, nil
		}
		return 0, nil
	}
	got := CorrelateByFavicon(context.Background(), []string{"1.2.3.4", "5.6.7.8"}, 42, fetch)
	if len(got) != 1 || got[0] != "1.2.3.4" {
		t.Errorf("CorrelateByFavicon() = %v", got)
	}
}

func TestEnrichResultCDN(t *testing.T) {
	r := &models.Result{Server: "cloudflare"}
	h := http.Header{}
	h.Set("CF-RAY", "x")
	EnrichResult(r, h, nil, false, nil)
	if !r.IsCDNProxied || r.CDNProvider != "Cloudflare" {
		t.Errorf("EnrichResult CDN = %v %q", r.IsCDNProxied, r.CDNProvider)
	}
	if r.PotentialOriginIPs == nil {
		t.Error("expected non-nil PotentialOriginIPs slice")
	}
}

func TestLooksLikeIP(t *testing.T) {
	if !looksLikeIP("192.168.1.1") {
		t.Error("expected ipv4 match")
	}
	if looksLikeIP("not-an-ip") {
		t.Error("expected reject")
	}
}

func TestCnameMatchesSink(t *testing.T) {
	cases := []struct {
		target string
		want   bool
	}{
		{"victim.github.io", true},
		{"app.herokuapp.com", false},
		{"cdn.cloudfront.net", true},
		{"safe.example.com", false},
		{"pages.github.io", true},
	}
	for _, tc := range cases {
		if got := cnameMatchesSink(tc.target); got != tc.want {
			t.Errorf("cnameMatchesSink(%q) = %v want %v", tc.target, got, tc.want)
		}
	}
}

func TestDiscoverEmptyDomain(t *testing.T) {
	_, err := Discover(context.Background(), "", nil)
	if err == nil || !strings.Contains(err.Error(), "empty domain") {
		t.Errorf("Discover() err = %v", err)
	}
}

func TestDetectCDNCloudFront(t *testing.T) {
	h := http.Header{}
	h.Set("X-Amz-Cf-Id", "abc")
	proxied, provider := DetectCDN(h, "")
	if !proxied || provider != "AWS CloudFront" {
		t.Errorf("got %v %q", proxied, provider)
	}
}

func TestEnrichResultOriginFallback(t *testing.T) {
	r := &models.Result{FaviconMMH3: 0}
	findings := &Findings{CandidateIPs: []string{"203.0.113.1", "203.0.113.2"}}
	fetch := func(ctx context.Context, host string) (int32, error) { return 0, nil }
	EnrichResult(r, http.Header{}, findings, true, fetch)
	if len(r.PotentialOriginIPs) != 2 {
		t.Errorf("fallback origin IPs = %v", r.PotentialOriginIPs)
	}
}

func TestCorrelateByFaviconNilFetch(t *testing.T) {
	got := CorrelateByFavicon(context.Background(), []string{"1.2.3.4"}, 42, nil)
	if got != nil {
		t.Errorf("expected nil, got %v", got)
	}
}

func TestFindingsStruct(t *testing.T) {
	f := Findings{
		MailHostnames: []string{"mx.example.com"},
		SPFRanges:     []string{"ip4:203.0.113.0/24"},
		CandidateIPs:  []string{"203.0.113.10"},
	}
	if len(f.MailHostnames) != 1 || len(f.CandidateIPs) != 1 {
		t.Errorf("Findings = %+v", f)
	}
}
