// Package dns provides a concurrent, bounded-concurrency DNS resolver
// designed for high-throughput subdomain enumeration workloads.
//
// Key design decisions:
//   - A single *net.Resolver instance is reused across all goroutines
//     (it is documented as safe for concurrent use).
//   - The worker pool is bounded by Config.Workers to prevent fd exhaustion.
//   - Each lookup runs under its own context with Config.Timeout so a slow
//     nameserver cannot block the entire pipeline.
package dns

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

// Config controls resolver behaviour.  Zero values are overridden by
// sensible defaults inside NewResolver.
type Config struct {
	// Nameservers is an optional list of custom DNS resolvers in
	// "host:port" format (e.g. ["8.8.8.8:53", "1.1.1.1:53"]).
	// When empty the system resolver is used.
	Nameservers []string

	// Workers is the maximum number of concurrent DNS goroutines.
	// Defaults to 100 when zero.
	Workers int

	// Timeout is the per-lookup deadline.  Defaults to 5 s when zero.
	Timeout time.Duration
}

func (c *Config) withDefaults() *Config {
	out := *c // copy so we don't mutate caller's value
	if out.Workers <= 0 {
		out.Workers = 100
	}
	if out.Timeout <= 0 {
		out.Timeout = 5 * time.Second
	}
	return &out
}

// ---------------------------------------------------------------------------
// Result
// ---------------------------------------------------------------------------

// LookupResult holds the outcome of a single DNS resolution attempt.
type LookupResult struct {
	// Host is the input hostname that was looked up.
	Host string

	// IPs contains the resolved addresses (A / AAAA records).
	// Empty when the host does not resolve or an error occurred.
	IPs []string

	// Err is non-nil when the lookup failed.
	Err error
}

// Resolved returns true when at least one IP was found without error.
func (r *LookupResult) Resolved() bool {
	return r.Err == nil && len(r.IPs) > 0
}

// ---------------------------------------------------------------------------
// Resolver
// ---------------------------------------------------------------------------

// Resolver performs concurrent DNS lookups with bounded parallelism.
type Resolver struct {
	cfg    *Config
	native *net.Resolver
}

// NewResolver constructs a Resolver from cfg, applying defaults for any
// zero-value fields.  It returns an error only when a custom nameserver
// address is malformed.
func NewResolver(cfg Config) (*Resolver, error) {
	c := cfg.withDefaults()

	nr, err := buildNetResolver(c.Nameservers)
	if err != nil {
		return nil, fmt.Errorf("dns: invalid nameserver config: %w", err)
	}

	return &Resolver{cfg: c, native: nr}, nil
}

// buildNetResolver constructs a *net.Resolver that uses the supplied list
// of nameservers via a custom dialer, or returns the default resolver when
// the list is empty.
func buildNetResolver(nameservers []string) (*net.Resolver, error) {
	if len(nameservers) == 0 {
		return net.DefaultResolver, nil
	}

	// Validate addresses up-front so the caller gets a clear error.
	for _, ns := range nameservers {
		if _, _, err := net.SplitHostPort(ns); err != nil {
			return nil, fmt.Errorf("bad nameserver %q: %w", ns, err)
		}
	}

	idx := 0
	var mu sync.Mutex

	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _ string, _ string) (net.Conn, error) {
			mu.Lock()
			ns := nameservers[idx%len(nameservers)]
			idx++
			mu.Unlock()

			d := net.Dialer{}
			return d.DialContext(ctx, "udp", ns)
		},
	}, nil
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

// ResolveAll drains the hosts channel, performs concurrent A/AAAA lookups,
// and sends each LookupResult to the returned channel, which is closed when
// all goroutines finish.
//
// The caller controls back-pressure by controlling how fast it reads from
// the output channel and writes to hosts.
//
// ctx cancellation propagates into every in-flight lookup and causes
// remaining items in hosts to be drained without resolution.
func (r *Resolver) ResolveAll(ctx context.Context, hosts <-chan string) <-chan LookupResult {
	out := make(chan LookupResult, r.cfg.Workers)

	go func() {
		defer close(out)

		sem := make(chan struct{}, r.cfg.Workers)
		var wg sync.WaitGroup

		for host := range hosts {
			// Respect context cancellation: stop consuming the input channel.
			if ctx.Err() != nil {
				break
			}

			sem <- struct{}{}
			wg.Add(1)

			go func(h string) {
				defer func() {
					<-sem
					wg.Done()
				}()

				result := r.lookup(ctx, h)

				// Non-blocking send so a slow consumer cannot deadlock the pool.
				select {
				case out <- result:
				case <-ctx.Done():
				}
			}(host)
		}

		wg.Wait()
	}()

	return out
}

// lookup performs a single LookupHost call with the configured timeout.
func (r *Resolver) lookup(ctx context.Context, host string) LookupResult {
	lookupCtx, cancel := context.WithTimeout(ctx, r.cfg.Timeout)
	defer cancel()

	addrs, err := r.native.LookupHost(lookupCtx, host)
	if err != nil {
		return LookupResult{Host: host, Err: err}
	}

	return LookupResult{Host: host, IPs: addrs}
}
