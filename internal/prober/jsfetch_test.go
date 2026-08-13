package prober

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestExtractJSURLs(t *testing.T) {
	html := `<html>
	<script src="/static/app.min.js"></script>
	<script src="https://cdn.example.com/bundle.js?v=1"></script>
	<script src="data:text/javascript,void(0)"></script>
	</html>`
	base := "https://example.com/page"

	got := extractJSURLs(html, base)
	if len(got) < 2 {
		t.Fatalf("extractJSURLs() = %v, want at least 2 URLs", got)
	}
	if !strings.Contains(got[0], "app.min.js") {
		t.Errorf("missing app.min.js in %v", got)
	}
}

func TestFetchJSBodies(t *testing.T) {
	var mu sync.Mutex
	fetched := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			fmt.Fprint(w, `<html><script src="/a.js"></script><script src="/b.js"></script></html>`)
		case "/a.js", "/b.js":
			mu.Lock()
			fetched++
			mu.Unlock()
			if r.URL.Path == "/a.js" {
				fmt.Fprint(w, `fetch("/api/v1/users")`)
			} else {
				fmt.Fprint(w, `const x = "/graphql"`)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	client := &http.Client{Timeout: 3 * time.Second}
	html := `<html><script src="/a.js"></script><script src="/b.js"></script></html>`
	bodies := fetchJSBodies(context.Background(), client, srv.URL+"/", html, defaultJSFetchOptions())

	mu.Lock()
	n := fetched
	mu.Unlock()
	if n != 2 {
		t.Errorf("expected 2 JS fetches, got %d", n)
	}
	if len(bodies) != 2 {
		t.Fatalf("bodies = %d, want 2", len(bodies))
	}

	eps := MineEndpoints(append([]string{html}, bodies...)...)
	want := map[string]struct{}{"/api/v1/users": {}, "/graphql": {}}
	for _, ep := range eps {
		delete(want, ep)
	}
	if len(want) > 0 {
		t.Errorf("missing endpoints %v in %v", want, eps)
	}
}

func TestFetchJSBodiesRespectsMaxFiles(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".js") {
			fmt.Fprint(w, `"/api/v1/x"`)
			return
		}
		fmt.Fprint(w, `<html>`)
		for i := 0; i < 20; i++ {
			fmt.Fprintf(w, `<script src="/f%d.js"></script>`, i)
		}
		fmt.Fprint(w, `</html>`)
	}))
	defer srv.Close()

	client := &http.Client{Timeout: 3 * time.Second}
	html := strings.Repeat(`<script src="/f0.js"></script>`, 1)
	for i := 0; i < 20; i++ {
		html += fmt.Sprintf(`<script src="/f%d.js"></script>`, i)
	}

	opts := defaultJSFetchOptions()
	opts.MaxFiles = 3
	bodies := fetchJSBodies(context.Background(), client, srv.URL+"/", html, opts)
	if len(bodies) > 3 {
		t.Errorf("expected at most 3 bodies, got %d", len(bodies))
	}
}
