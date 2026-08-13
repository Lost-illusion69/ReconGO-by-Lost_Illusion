package prober

import (
	"crypto/tls"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/http2"
)

func newTransport(opts Options) (*http.Transport, error) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // intentional for recon probing
		},
		ForceAttemptHTTP2: true,
	}

	if err := http2.ConfigureTransport(transport); err != nil {
		return nil, fmt.Errorf("prober: configure http2: %w", err)
	}

	proxyURL := strings.TrimSpace(opts.ProxyURL)
	if proxyURL == "" {
		transport.Proxy = http.ProxyFromEnvironment
		return transport, nil
	}

	u, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("prober: parse proxy URL: %w", err)
	}

	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		transport.Proxy = http.ProxyURL(u)
	case "socks5", "socks5h":
		dialer, err := socks5Dialer(u)
		if err != nil {
			return nil, err
		}
		transport.Proxy = nil
		transport.DialContext = dialer.DialContext
	default:
		return nil, fmt.Errorf("prober: unsupported proxy scheme %q (want http, https, socks5)", u.Scheme)
	}

	return transport, nil
}

func newClient(opts Options) (*http.Client, error) {
	opts = opts.withDefaults()
	transport, err := newTransport(opts)
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Timeout:   opts.Timeout,
		Transport: transport,
	}, nil
}

func applyDelay(base time.Duration) {
	if base <= 0 {
		return
	}
	jitter := time.Duration(rand.Int64N(int64(base)))
	time.Sleep(base + jitter)
}

func applyHeaders(req *http.Request, opts Options) {
	ua := pickUserAgent(opts.RandomAgent)
	req.Header.Set("User-Agent", ua)

	// Diagnostic / bypass headers (skipped when caller already set them).
	setDefault := func(k, v string) {
		if req.Header.Get(k) == "" {
			req.Header.Set(k, v)
		}
	}
	setDefault("X-Forwarded-For", "127.0.0.1")
	setDefault("X-Real-IP", "127.0.0.1")
	setDefault("X-Debug", "1")

	for k, v := range opts.Headers {
		req.Header.Set(k, v)
	}
}
