package sources

import (
	"fmt"
	"strings"
)

// ---------------------------------------------------------------------------
// Wordlist source
// ---------------------------------------------------------------------------

const wordlistName = "wordlist"

// Wordlist is a static source that provides common subdomain prefixes.
// It acts as a fallback or baseline enum, ensuring we always check common
// targets like "www", "api", "dev" even if public APIs are down.
type Wordlist struct {
	prefixes []string
}

// NewWordlist returns a Wordlist source initialized with a default top-N list.
func NewWordlist() *Wordlist {
	return &Wordlist{
		prefixes: []string{
			"www", "mail", "api", "dev", "staging", "vpn",
			"admin", "portal", "auth", "m", "blog", "status",
			"test", "gateway", "app",
		},
	}
}

// Name implements sources.Source.
func (w *Wordlist) Name() string { return wordlistName }

// Fetch implements sources.Source.
// It constructs `<prefix>.<domain>` for each prefix.
func (w *Wordlist) Fetch(domain string) ([]Result, error) {
	// The domain string might contain spaces or upper case characters from user input,
	// ensure it's normalized for prefixing.
	cleanDomain := strings.ToLower(strings.TrimSpace(domain))

	results := make([]Result, 0, len(w.prefixes))
	for _, p := range w.prefixes {
		results = append(results, Result{
			Value:  fmt.Sprintf("%s.%s", p, cleanDomain),
			Source: wordlistName,
		})
	}

	return results, nil
}
