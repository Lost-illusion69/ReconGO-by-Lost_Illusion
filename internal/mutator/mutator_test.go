package mutator

import (
	"context"
	"testing"
)

func TestParseHost(t *testing.T) {
	p, ok := parseHost("api-dev-us-east.example.com", "example.com")
	if !ok {
		t.Fatal("parseHost failed")
	}
	if p.functional != "api" || p.env != "dev" || p.region != "us-east" {
		t.Errorf("got func=%q env=%q region=%q", p.functional, p.env, p.region)
	}
}

func TestCrossMutateEnvironments(t *testing.T) {
	e := New(Config{MaxMutations: 100, RootDomain: "target.com"})
	out := make(chan string, 32)
	ctx := context.Background()

	e.Mutate(ctx, "api-dev-us-east.target.com", out)
	close(out)

	got := make(map[string]struct{})
	for h := range out {
		got[h] = struct{}{}
	}

	for _, env := range []string{"stage", "prod", "test"} {
		want := "api-" + env + "-us-east.target.com"
		if _, ok := got[want]; !ok {
			t.Errorf("missing env mutation %q, got %v", want, got)
		}
	}
	if _, ok := got["api-dev-us-east.target.com"]; ok {
		t.Error("should not re-emit original host")
	}
}

func TestCrossMutateRegions(t *testing.T) {
	e := New(Config{MaxMutations: 100, RootDomain: "target.com"})
	out := make(chan string, 32)
	ctx := context.Background()

	e.Mutate(ctx, "api-dev-us-east.target.com", out)
	close(out)

	got := make(map[string]struct{})
	for h := range out {
		got[h] = struct{}{}
	}

	for _, region := range []string{"us-west", "eu-central", "asia"} {
		parts := stringsSplitRegion(region)
		want := "api-dev-" + parts + ".target.com"
		if _, ok := got[want]; !ok {
			t.Errorf("missing region mutation %q", want)
		}
	}
}

func stringsSplitRegion(region string) string {
	// rebuild uses hyphen join for region parts
	switch region {
	case "us-west":
		return "us-west"
	case "eu-central":
		return "eu-central"
	case "asia":
		return "asia"
	default:
		return region
	}
}

func TestMutationCap(t *testing.T) {
	e := New(Config{MaxMutations: 3, RootDomain: "example.com"})
	out := make(chan string, 16)
	ctx := context.Background()

	e.Mutate(ctx, "api-dev-us-east.example.com", out)
	close(out)

	count := 0
	for range out {
		count++
	}
	if count > 3 {
		t.Errorf("emitted %d, want ≤ 3", count)
	}
}

func TestVisitedPreventsLoop(t *testing.T) {
	e := New(Config{MaxMutations: 500, RootDomain: "example.com"})
	out := make(chan string, 8)
	ctx := context.Background()

	e.Mutate(ctx, "api-dev-us-east.example.com", out)
	first := e.Emitted()

	// Re-mutating same host must not emit again.
	e.Mutate(ctx, "api-dev-us-east.example.com", out)
	if e.Emitted() != first {
		t.Errorf("re-mutate emitted more: %d vs %d", e.Emitted(), first)
	}
}

func TestTokenize(t *testing.T) {
	tokens := tokenize("api_dev.us-east")
	want := []string{"api", "dev", "us", "east"}
	if len(tokens) != len(want) {
		t.Fatalf("tokens = %v, want %v", tokens, want)
	}
	for i := range want {
		if tokens[i] != want[i] {
			t.Errorf("token[%d] = %q, want %q", i, tokens[i], want[i])
		}
	}
}
