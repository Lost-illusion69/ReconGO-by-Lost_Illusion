package cors

import (
	"context"
	"testing"
)

// fakeProbe builds a ProbeFunc that answers with a canned ACAO/ACAC pair.
func fakeProbe(acao, acac string) ProbeFunc {
	return func(_ context.Context, _, _ string) (Response, error) {
		return Response{StatusCode: 200, ACAO: acao, ACAC: acac}, nil
	}
}

func TestCheckFlagsReflectedOriginWithCredentials(t *testing.T) {
	found := Check(context.Background(), "https://api.target.com", "api.target.com",
		fakeProbe("https://evil.example", "true"))
	if len(found) == 0 {
		t.Fatal("expected findings for reflected origin with credentials")
	}
	if found[0].Severity != High {
		t.Errorf("severity = %s, want high", found[0].Severity)
	}
	if !found[0].AllowCredentials {
		t.Error("AllowCredentials should be true")
	}
	if found[0].Reflected != "https://evil.example" {
		t.Errorf("reflected = %q", found[0].Reflected)
	}
}

func TestCheckFlagsReflectedOriginWithoutCredentials(t *testing.T) {
	found := Check(context.Background(), "https://api.target.com", "api.target.com",
		fakeProbe("https://evil.example", "false"))
	if len(found) == 0 {
		t.Fatal("expected findings for reflected origin without credentials")
	}
	for _, f := range found {
		if f.Severity != Medium {
			t.Errorf("severity = %s, want medium", f.Severity)
		}
		if f.AllowCredentials {
			t.Error("AllowCredentials should be false")
		}
	}
}

func TestCheckFlagsNullOriginReflection(t *testing.T) {
	// Server reflects "null" only for the null-origin probe.
	probe := func(_ context.Context, _, origin string) (Response, error) {
		if origin == "null" {
			return Response{ACAO: "null", ACAC: "true"}, nil
		}
		return Response{ACAO: ""}, nil
	}
	found := Check(context.Background(), "https://api.target.com", "api.target.com", probe)
	if len(found) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d: %+v", len(found), found)
	}
	if found[0].SentOrigin != "null" || found[0].Severity != Medium {
		t.Errorf("unexpected finding: %+v", found[0])
	}
}

func TestCheckSkipsWildcardACAO(t *testing.T) {
	found := Check(context.Background(), "https://api.target.com", "api.target.com",
		fakeProbe("*", "true"))
	if len(found) != 0 {
		t.Errorf("wildcard ACAO must not be reported, got %+v", found)
	}
}

func TestCheckSkipsCleanServer(t *testing.T) {
	found := Check(context.Background(), "https://api.target.com", "api.target.com",
		fakeProbe("", ""))
	if len(found) != 0 {
		t.Errorf("expected no findings on strict CORS, got %+v", found)
	}
}

func TestCheckTrustedSuffixBypass(t *testing.T) {
	suffix := "api.target.com.evil.example"
	probe := func(_ context.Context, _, origin string) (Response, error) {
		if origin == "https://"+suffix {
			return Response{ACAO: origin, ACAC: "true"}, nil
		}
		return Response{ACAO: ""}, nil
	}
	found := Check(context.Background(), "https://api.target.com", "api.target.com", probe)
	if len(found) != 1 {
		t.Fatalf("expected 1 suffix-bypass finding, got %+v", found)
	}
	if found[0].Severity != High {
		t.Errorf("severity = %s, want high", found[0].Severity)
	}
}

func TestCheckToleratesProbeErrors(t *testing.T) {
	probe := func(_ context.Context, _, _ string) (Response, error) {
		return Response{}, context.Canceled
	}
	found := Check(context.Background(), "https://api.target.com", "api.target.com", probe)
	if len(found) != 0 {
		t.Errorf("probe errors must not produce findings, got %+v", found)
	}
}

func TestCheckNilProbeAndEmptyURL(t *testing.T) {
	ctx := context.Background()
	if got := Check(ctx, "", "h", fakeProbe("*", "")); len(got) != 0 {
		t.Errorf("empty baseURL should yield nothing, got %+v", got)
	}
	if got := Check(ctx, "https://x", "h", nil); len(got) != 0 {
		t.Errorf("nil probe should yield nothing, got %+v", got)
	}
}

func TestCheckHonorsCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := Check(ctx, "https://x", "h", fakeProbe("*", "")); len(got) != 0 {
		t.Errorf("cancelled context should yield nothing, got %+v", got)
	}
}

func TestAttackOriginsIncludeHostSuffix(t *testing.T) {
	origins := attackOrigins("api.target.com")
	want := "https://api.target.com.evil.example"
	found := false
	for _, o := range origins {
		if o.value == want {
			found = true
		}
	}
	if !found {
		t.Errorf("missing suffix-bypass origin %q in %+v", want, origins)
	}
}
