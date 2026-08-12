// Package sources defines the foundational interface that all external
// data-source integrations must satisfy, along with shared types used
// across the engine.
package sources

import "fmt"

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

// Result holds a single discovered asset returned by a Source.
// Using a struct instead of a bare string lets us carry provenance
// metadata without breaking the interface in future revisions.
type Result struct {
	// Value is the raw asset string (e.g. "api.example.com").
	Value string

	// Source is the name of the integration that produced the result
	// (e.g. "crtsh", "hackertarget").
	Source string
}

// ---------------------------------------------------------------------------
// Source interface
// ---------------------------------------------------------------------------

// Source is the contract every external API integration must implement.
//
// Implementations are expected to be stateless, safe for concurrent use,
// and must handle their own rate-limiting / retry logic internally.
//
// Example implementation skeleton:
//
//	type CrtSH struct{}
//
//	func (c *CrtSH) Name() string { return "crtsh" }
//
//	func (c *CrtSH) Fetch(domain string) ([]Result, error) {
//	    // … HTTP call, JSON parse, return []Result
//	}
type Source interface {
	// Name returns a short, human-readable identifier for the source.
	// It is used for logging, metrics, and the Result.Source field.
	Name() string

	// Fetch queries the source for assets associated with the given domain.
	// It must return a non-nil slice (possibly empty) on success and a
	// non-nil error on failure.  It must NOT panic.
	Fetch(domain string) ([]Result, error)
}

// ---------------------------------------------------------------------------
// Sentinel error type
// ---------------------------------------------------------------------------

// SourceError wraps an upstream API error with the name of the source
// that produced it, enabling callers to distinguish failures per-source
// without losing the original error message.
type SourceError struct {
	SourceName string
	Err        error
}

// Error implements the error interface.
func (e *SourceError) Error() string {
	return fmt.Sprintf("[%s] %v", e.SourceName, e.Err)
}

// Unwrap satisfies the errors.Is / errors.As chain so callers can inspect
// the underlying error without type-asserting SourceError themselves.
func (e *SourceError) Unwrap() error {
	return e.Err
}

// WrapError is a convenience constructor that wraps any error with the
// given source name, returning nil when err is nil (safe to use inline).
func WrapError(sourceName string, err error) error {
	if err == nil {
		return nil
	}
	return &SourceError{SourceName: sourceName, Err: err}
}
