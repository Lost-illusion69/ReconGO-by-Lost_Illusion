// Package prober performs active HTTP/HTTPS web probing against resolved hosts.
//
// This package re-exports models.Result as AssetResult and delegates probing
// to internal/prober for MMH3 fingerprinting.
package prober

import (
	"context"

	intprober "github.com/Lost-illusion69/recongo/internal/prober"
	"github.com/Lost-illusion69/recongo/models"
)

// maxBodyBytes is re-exported for tests that assert body limits.
const maxBodyBytes = intprober.MaxBodyBytes

// AssetResult is the canonical probe output type.
type AssetResult = models.Result

// Options configures HTTP probe behaviour.
type Options = intprober.Options

// ParseHeaders parses comma-separated custom header pairs.
func ParseHeaders(raw string) (map[string]string, error) {
	return intprober.ParseHeaders(raw)
}

// Probe attempts HTTPS then HTTP against host with the supplied options.
func Probe(host string, opts Options) (*AssetResult, error) {
	return intprober.Probe(host, opts)
}

// ExtractTitle exposes HTML title parsing for legacy tests.
func ExtractTitle(body []byte) string {
	return intprober.ExtractTitle(body)
}

// MineEndpoints exposes route mining for tests.
func MineEndpoints(body []byte) []string {
	return intprober.MineEndpoints(string(body))
}

// DefaultWordlistPath is the built-in SecLists directory wordlist location.
func DefaultWordlistPath() string {
	return intprober.DefaultWordlistPath()
}

// LoadWordlist reads and normalizes a content-discovery wordlist file.
func LoadWordlist(path string) ([]string, error) {
	return intprober.LoadWordlist(path)
}

// FuzzEligible reports whether a probe status should trigger directory fuzzing.
func FuzzEligible(status int) bool {
	return intprober.FuzzEligible(status)
}

// FuzzEligibleWith401 reports fuzz eligibility, optionally accepting 401-gated apps.
func FuzzEligibleWith401(status int, allowUnauthorized bool) bool {
	return intprober.FuzzEligibleWith401(status, allowUnauthorized)
}

// FuzzConfig drives extension expansion and recursive directory descent.
type FuzzConfig = intprober.FuzzConfig

// FuzzWithConfig runs extension-aware, optionally recursive content discovery.
func FuzzWithConfig(ctx context.Context, cfg FuzzConfig) ([]models.FuzzHit, error) {
	return intprober.FuzzWithConfig(ctx, cfg)
}

// Fuzz runs concurrent path discovery against a live web origin.
func Fuzz(ctx context.Context, baseURL string, words []string, opts Options, workers int) ([]models.FuzzHit, error) {
	return intprober.Fuzz(ctx, baseURL, words, opts, workers)
}

// MergeFuzzIntoEndpoints unions fuzz hits into the mined endpoint list.
func MergeFuzzIntoEndpoints(endpoints []string, hits []models.FuzzHit) []string {
	return intprober.MergeFuzzIntoEndpoints(endpoints, hits)
}
