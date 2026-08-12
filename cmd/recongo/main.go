// ReconGo — production-grade concurrent asset reconnaissance engine.
//
// Usage:
//
//	recongo -domain example.com [-workers 50] [-dns-workers 100] [-timeout 5s] [-resolvers 8.8.8.8:53,1.1.1.1:53] [-verbose]
//
// The binary exits with code 0 on success, 1 on usage/config errors,
// and 2 when terminated by signal.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Lost-illusion69/recongo/pkg/dns"
	"github.com/Lost-illusion69/recongo/pkg/engine"
	"github.com/Lost-illusion69/recongo/pkg/sources"
)

// version is stamped at build time via -ldflags="-X main.version=<tag>".
// Falls back to "dev" when running via `go run`.
var version = "dev"

// ---------------------------------------------------------------------------
// CLI flags
// ---------------------------------------------------------------------------

// config holds every value parsed from the command line.  It is defined as
// a plain struct (not a global) and passed by pointer throughout the call
// chain so each layer only sees what it needs.
type config struct {
	domain      string
	workers     int
	dnsWorkers  int
	timeout     time.Duration
	resolvers   string // comma-separated "host:port" list
	verbose     bool
	showVersion bool
}

func parseFlags(args []string) (*config, error) {
	fs := flag.NewFlagSet("recongo", flag.ContinueOnError)

	cfg := &config{}

	fs.StringVar(&cfg.domain, "domain", "", "Target domain to enumerate (required)")
	fs.IntVar(&cfg.workers, "workers", 50, "Number of concurrent source-fetch workers")
	fs.IntVar(&cfg.dnsWorkers, "dns-workers", 100, "Number of concurrent DNS resolution workers")
	fs.DurationVar(&cfg.timeout, "timeout", 5*time.Second, "Per-lookup DNS timeout")
	fs.StringVar(&cfg.resolvers, "resolvers", "", "Comma-separated custom DNS resolvers (e.g. 8.8.8.8:53,1.1.1.1:53)")
	fs.BoolVar(&cfg.verbose, "verbose", false, "Enable debug-level logging")
	fs.BoolVar(&cfg.showVersion, "version", false, "Print version and exit")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	return cfg, nil
}

// ---------------------------------------------------------------------------
// Logger construction
// ---------------------------------------------------------------------------

func buildLogger(verbose bool) *slog.Logger {
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}

	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: level,
	})

	return slog.New(handler)
}

// ---------------------------------------------------------------------------
// Source registry
// ---------------------------------------------------------------------------

// registeredSources returns the list of all active Source implementations.
// Adding a new integration is as simple as appending it here.
func registeredSources() []sources.Source {
	return []sources.Source{
		// Placeholder sources included to demonstrate the pipeline.
		// Replace / extend with real implementations (CrtSH, HackerTarget, etc.)
		newNoopSource("crtsh"),
		newNoopSource("hackertarget"),
		newNoopSource("threatcrowd"),
	}
}

// ---------------------------------------------------------------------------
// noopSource — demonstration stub that satisfies the Source interface.
// Replace with real HTTP-based implementations in pkg/sources/<name>.go.
// ---------------------------------------------------------------------------

type noopSource struct{ name string }

func newNoopSource(name string) *noopSource { return &noopSource{name: name} }

func (n *noopSource) Name() string { return n.name }

func (n *noopSource) Fetch(domain string) ([]sources.Result, error) {
	// Real implementations would perform an HTTP call here.
	// Return a synthetic subdomain so the pipeline is visibly exercised.
	synthetic := fmt.Sprintf("stub-%s.%s", n.name, domain)
	return []sources.Result{
		{Value: synthetic, Source: n.name},
	}, nil
}

// ---------------------------------------------------------------------------
// Pipeline wiring
// ---------------------------------------------------------------------------

// run wires the engine and DNS resolver into a single pipeline and blocks
// until all results are processed or ctx is cancelled.
//
//	domains channel  →  engine (source fetch)  →  dns (resolver)  →  stdout
func run(ctx context.Context, cfg *config, log *slog.Logger) error {
	// Build the list of custom nameservers (empty = system default).
	var nameservers []string
	if cfg.resolvers != "" {
		for _, r := range strings.Split(cfg.resolvers, ",") {
			r = strings.TrimSpace(r)
			if r != "" {
				nameservers = append(nameservers, r)
			}
		}
	}

	// Construct the DNS resolver.
	resolver, err := dns.NewResolver(dns.Config{
		Nameservers: nameservers,
		Workers:     cfg.dnsWorkers,
		Timeout:     cfg.timeout,
	})
	if err != nil {
		return fmt.Errorf("dns resolver init: %w", err)
	}

	// Construct the source-fetch engine.
	eng := engine.New(
		engine.Config{
			Workers:          cfg.workers,
			ResultBufferSize: cfg.workers * 10,
		},
		registeredSources(),
		log,
	)

	// Seed the domains channel with the single target domain.
	// In a future revision this channel can be fed by a file reader,
	// a pipe, or a stdin scanner without changing any other layer.
	domainCh := make(chan string, 1)
	go func() {
		defer close(domainCh)
		select {
		case domainCh <- cfg.domain:
		case <-ctx.Done():
		}
	}()

	// Stage 1: source fetching  →  raw asset strings.
	resultCh := eng.Run(ctx, domainCh)

	// Stage 2: pipe raw asset values into the DNS resolver.
	hostCh := make(chan string, cfg.dnsWorkers)
	go func() {
		defer close(hostCh)
		for r := range resultCh {
			select {
			case hostCh <- r.Value:
			case <-ctx.Done():
				return
			}
		}
	}()

	// Stage 3: resolve and print.
	resolvedCh := resolver.ResolveAll(ctx, hostCh)

	found := 0
	for lr := range resolvedCh {
		if lr.Err != nil {
			log.DebugContext(ctx, "dns lookup failed",
				slog.String("host", lr.Host),
				slog.String("error", lr.Err.Error()),
			)
			continue
		}
		found++
		fmt.Printf("[+] %-50s %s\n", lr.Host, strings.Join(lr.IPs, ", "))
	}

	log.InfoContext(ctx, "scan complete", slog.Int("resolved", found))
	return nil
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

func main() {
	cfg, err := parseFlags(os.Args[1:])
	if err != nil {
		// flag.ContinueOnError already printed the error.
		os.Exit(1)
	}

	if cfg.showVersion {
		fmt.Printf("recongo %s\n", version)
		os.Exit(0)
	}

	if cfg.domain == "" {
		fmt.Fprintln(os.Stderr, "error: -domain is required")
		fmt.Fprintln(os.Stderr, "usage: recongo -domain <target> [options]")
		os.Exit(1)
	}

	log := buildLogger(cfg.verbose)

	// Root context cancelled on SIGINT / SIGTERM so every goroutine can
	// detect shutdown via ctx.Done() — no global state required.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.Info("recongo starting",
		slog.String("version", version),
		slog.String("domain", cfg.domain),
		slog.Int("workers", cfg.workers),
		slog.Int("dns-workers", cfg.dnsWorkers),
	)

	if err := run(ctx, cfg, log); err != nil {
		log.Error("fatal", slog.String("error", err.Error()))
		os.Exit(1)
	}

	// Distinguish clean exit from signal-induced exit so callers / scripts
	// can detect cancellation vs. genuine completion.
	if ctx.Err() != nil {
		log.Warn("terminated by signal")
		os.Exit(2)
	}
}
