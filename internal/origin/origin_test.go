package origin

import (
	"context"
	"net/http"
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
