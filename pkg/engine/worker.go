// Package engine implements the orchestration layer that ties together
// the source-fetching pipeline and the DNS resolution pipeline.
//
// Architecture (data flow):
//
//	                 ┌─────────────┐
//	                 │  domains in │  (buffered input channel)
//	                 └──────┬──────┘
//	                        │  fan-out to N workers
//	          ┌─────────────┼─────────────┐
//	          ▼             ▼             ▼
//	     [worker 0]   [worker 1]  … [worker N-1]
//	          │             │             │
//	          └─────────────┼─────────────┘
//	                        │  gather results
//	                 ┌──────▼──────┐
//	                 │  results ch │  (buffered output channel)
//	                 └─────────────┘
//
// Each worker calls every registered Source.Fetch for the domain it
// receives, emitting one sources.Result per discovered asset.
package engine

import (
	"context"
	"log/slog"
	"sync"

	"github.com/Lost-illusion69/recongo/pkg/sources"
)

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

// Config holds all tunables for the worker pool.
type Config struct {
	// Workers is the maximum number of goroutines fetching from sources
	// simultaneously.  Defaults to 50 when zero.
	Workers int

	// ResultBufferSize is the capacity of the output channel.
	// A larger buffer reduces backpressure at the cost of memory.
	// Defaults to 500 when zero.
	ResultBufferSize int
}

func (c Config) withDefaults() Config {
	if c.Workers <= 0 {
		c.Workers = 50
	}
	if c.ResultBufferSize <= 0 {
		c.ResultBufferSize = 500
	}
	return c
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

// Engine orchestrates concurrent source queries for a stream of domains.
type Engine struct {
	cfg     Config
	sources []sources.Source
	log     *slog.Logger
}

// New constructs an Engine with the supplied configuration and source list.
// sources must not be nil or empty; an empty slice will produce no results.
func New(cfg Config, srcs []sources.Source, log *slog.Logger) *Engine {
	return &Engine{
		cfg:     cfg.withDefaults(),
		sources: srcs,
		log:     log,
	}
}

// ---------------------------------------------------------------------------
// Run
// ---------------------------------------------------------------------------

// Run starts the worker pool and returns a read-only channel of results.
//
// Callers send domains to the domains channel and close it when done.
// Run drains domains, queries every Source for each domain, and streams
// discovered assets to the returned channel.  The output channel is closed
// automatically once all workers finish.
//
// Cancelling ctx causes in-flight source fetches to be abandoned and no
// further domains to be consumed.
//
// Example usage:
//
//	domainCh := make(chan string, 10)
//	resultCh := eng.Run(ctx, domainCh)
//
//	go func() {
//	    defer close(domainCh)
//	    for _, d := range targets { domainCh <- d }
//	}()
//
//	for r := range resultCh {
//	    fmt.Println(r.Value)
//	}
func (e *Engine) Run(ctx context.Context, domains <-chan string) <-chan sources.Result {
	out := make(chan sources.Result, e.cfg.ResultBufferSize)

	// sem acts as a counting semaphore that caps the number of concurrently
	// active workers; this prevents unbounded goroutine spawning when the
	// input channel is pre-populated with thousands of domains.
	sem := make(chan struct{}, e.cfg.Workers)

	go func() {
		defer close(out)

		var wg sync.WaitGroup

		for domain := range domains {
			// Honour cancellation before spawning a new worker.
			if ctx.Err() != nil {
				e.log.WarnContext(ctx, "context cancelled, stopping domain consumption")
				break
			}

			sem <- struct{}{} // acquire slot
			wg.Add(1)

			go func(d string) {
				defer func() {
					<-sem // release slot
					wg.Done()
				}()

				e.processDomain(ctx, d, out)
			}(domain)
		}

		// Wait for all in-flight workers before closing out.
		wg.Wait()
	}()

	return out
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// processDomain queries every registered Source for the given domain and
// emits each discovered asset to the out channel.
// It is designed to be called inside a goroutine and must not panic.
func (e *Engine) processDomain(ctx context.Context, domain string, out chan<- sources.Result) {
	for _, src := range e.sources {
		// Re-check context before each source so we exit promptly on cancel.
		if ctx.Err() != nil {
			return
		}

		results, err := src.Fetch(domain)
		if err != nil {
			e.log.WarnContext(ctx, "source fetch failed",
				slog.String("source", src.Name()),
				slog.String("domain", domain),
				slog.String("error", err.Error()),
			)
			continue
		}

		e.log.DebugContext(ctx, "source fetch succeeded",
			slog.String("source", src.Name()),
			slog.String("domain", domain),
			slog.Int("count", len(results)),
		)

		for _, r := range results {
			select {
			case out <- r:
			case <-ctx.Done():
				return
			}
		}
	}
}
