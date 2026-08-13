// Package prober performs active HTTP/HTTPS web probing against resolved hosts.
//
// This package re-exports models.Result as AssetResult and delegates probing
// to internal/prober for MMH3 fingerprinting.
package prober

import (
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
	return intprober.MineEndpoints(body)
}
