package engine

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/Lost-illusion69/recongo/pkg/dns"
	"github.com/Lost-illusion69/recongo/pkg/prober"
)

// ---------------------------------------------------------------------------
// ProbeConfig
// ---------------------------------------------------------------------------

// ProbeConfig holds tunables for the HTTP probe worker pool.
type ProbeConfig struct {
	// Workers is the maximum number of concurrent HTTP probes.
	// Defaults to 50 when zero.
	Workers int

	// Timeout is the per-host HTTP probe deadline.
	// Defaults to 5 s when zero.
	Timeout time.Duration

	// Options carries adaptive traffic, header, and proxy settings.
	Options prober.Options

	// ResultBufferSize is the capacity of the output channel.
	// Defaults to Workers * 10 when zero.
	ResultBufferSize int
}

func (c ProbeConfig) withDefaults() ProbeConfig {
	if c.Workers <= 0 {
		c.Workers = 50
	}
	if c.Timeout <= 0 {
		c.Timeout = 5 * time.Second
	}
	if c.ResultBufferSize <= 0 {
		c.ResultBufferSize = c.Workers * 10
	}
	return c
}

// ---------------------------------------------------------------------------
// ProbePool
// ---------------------------------------------------------------------------

// ProbePool runs concurrent HTTP probes against DNS-resolved hosts.
type ProbePool struct {
	cfg ProbeConfig
	log *slog.Logger
}

// NewProbePool constructs a ProbePool with the supplied configuration.
func NewProbePool(cfg ProbeConfig, log *slog.Logger) *ProbePool {
	return &ProbePool{
		cfg: cfg.withDefaults(),
		log: log,
	}
}

// Run drains resolved, probes every alive host, and returns a channel of
// AssetResult values.  Hosts that failed DNS resolution (lr.Err != nil or
// empty IPs) are skipped.  Failed HTTP probes are logged at debug level and
// omitted from the output stream.
//
// The output channel is closed once every in-flight probe finishes.
// Cancelling ctx stops further consumption of resolved and abandons waiting
// sends on the output channel.
func (p *ProbePool) Run(ctx context.Context, resolved <-chan dns.LookupResult) <-chan prober.AssetResult {
	out := make(chan prober.AssetResult, p.cfg.ResultBufferSize)

	go func() {
		defer close(out)

		sem := make(chan struct{}, p.cfg.Workers)
		var wg sync.WaitGroup

		for lr := range resolved {
			if ctx.Err() != nil {
				p.log.WarnContext(ctx, "context cancelled, stopping probe consumption")
				break
			}

			// Only probe hosts that resolved successfully.
			if !lr.Resolved() {
				continue
			}

			sem <- struct{}{}
			wg.Add(1)

			go func(lookup dns.LookupResult) {
				defer func() {
					<-sem
					wg.Done()
				}()

				opts := p.cfg.Options
				opts.Timeout = p.cfg.Timeout
				result, err := prober.Probe(lookup.Host, opts)
				if err != nil {
					p.log.DebugContext(ctx, "http probe failed",
						slog.String("host", lookup.Host),
						slog.String("error", err.Error()),
					)
					return
				}

				// Attach the DNS-resolved IPs (Probe leaves them unset).
				result.IPs = lookup.IPs

				select {
				case out <- *result:
				case <-ctx.Done():
				}
			}(lr)
		}

		wg.Wait()
	}()

	return out
}
