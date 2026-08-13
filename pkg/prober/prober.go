// Package prober performs active HTTP/HTTPS web probing against resolved hosts.
//
// This package re-exports models.Result as AssetResult and delegates probing
// to internal/prober for MMH3 fingerprinting.
package prober

import (
	"time"

	intprober "github.com/Lost-illusion69/recongo/internal/prober"
	"github.com/Lost-illusion69/recongo/models"
)

// maxBodyBytes is re-exported for tests that assert body limits.
const maxBodyBytes = intprober.MaxBodyBytes

// AssetResult is the canonical probe output type.
type AssetResult = models.Result

// Probe attempts HTTPS then HTTP against host with Shodan-compatible MMH3 hashes.
func Probe(host string, timeout time.Duration) (*AssetResult, error) {
	return intprober.Probe(host, timeout)
}

// ExtractTitle exposes HTML title parsing for legacy tests.
func ExtractTitle(body []byte) string {
	return intprober.ExtractTitle(body)
}
