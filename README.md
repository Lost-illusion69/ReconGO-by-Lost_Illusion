<div align="center">

# ⚡ ReconGo

**Production-grade, concurrent multi-protocol asset reconnaissance engine — written in Go.**

[![CI](https://github.com/Lost-illusion69/ReconGO-by-Lost_Illusion/actions/workflows/ci.yml/badge.svg)](https://github.com/Lost-illusion69/ReconGO-by-Lost_Illusion/actions/workflows/ci.yml)
[![Go Version](https://img.shields.io/badge/go-1.22+-00ADD8?logo=go)](go.mod)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Go Report](https://goreportcard.com/badge/github.com/Lost-illusion69/recongo)](https://goreportcard.com/report/github.com/Lost-illusion69/recongo)

*Part of the [Lost-illusion69](https://github.com/Lost-illusion69) Security Engineering Toolkit — Project #1*

</div>

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [Adding a New Source](#adding-a-new-source)
- [Docker](#docker)
- [CI / CD Pipeline](#ci--cd-pipeline)
- [Defensive Context (Blue Team)](#-defensive-context-blue-team)
- [Roadmap](#roadmap)
- [License](#license)

---

## Overview

ReconGo is a high-performance CLI utility that concurrently queries multiple subdomain/asset APIs and resolves discovered hosts via DNS — all within a bounded goroutine worker pool designed to prevent memory spikes at scale.

It is built entirely on the **Go standard library** (no heavyweight frameworks) and follows the [Standard Go Project Layout](https://github.com/golang-standards/project-layout).

> **Legal notice:** This tool is intended for authorized security assessments, bug bounty programmes, and penetration tests only. Unauthorized use against systems you do not own or have explicit permission to test is illegal. The author accepts no liability for misuse.

---

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                      cmd/recongo/main.go                 │
│  CLI flags → signal context → pipeline orchestration     │
└────────────────────────┬─────────────────────────────────┘
                         │  chan string  (domains)
                         ▼
┌──────────────────────────────────────────────────────────┐
│                    pkg/engine/worker.go                  │
│  Bounded worker pool  (default 50 goroutines)            │
│  Fans out to every registered Source.Fetch(domain)       │
└────────────────────────┬─────────────────────────────────┘
                         │  chan sources.Result  (raw assets)
                         ▼
┌──────────────────────────────────────────────────────────┐
│                    pkg/dns/resolver.go                   │
│  Concurrent DNS resolver  (default 100 goroutines)       │
│  A/AAAA lookups with per-lookup context timeout          │
└────────────────────────┬─────────────────────────────────┘
                         │  chan dns.LookupResult
                         ▼
                     stdout  /  JSON  /  file
```

**Data flow is channel-driven and back-pressure-aware** — no goroutine can leak because every stage closes its output channel and respects `ctx.Done()`.

---

## Features

| Feature | Detail |
|---|---|
| **Worker pool** | Bounded by `-workers` flag (default 50); semaphore pattern via `chan struct{}` |
| **DNS resolver** | Bounded by `-dns-workers` (default 100); per-lookup `context.WithTimeout` |
| **Custom resolvers** | Pass comma-separated `host:port` nameservers via `-resolvers` |
| **Source interface** | Single `Fetch(domain) ([]Result, error)` contract — add integrations in minutes |
| **Graceful shutdown** | `signal.NotifyContext` propagates SIGINT/SIGTERM into every goroutine |
| **Structured logging** | `log/slog` with text handler; debug level via `-verbose` |
| **Zero dependencies** | Pure stdlib — no `go.sum` bloat, fast `go install` |
| **Static binary** | CGO disabled; runs on any Linux/mac/Windows without a runtime |
| **Multi-stage Docker** | `scratch` final image < 10 MB; non-root UID 65534 |

---

## Installation

### From source (recommended)

```bash
# Requires Go 1.22+
git clone https://github.com/Lost-illusion69/ReconGO-by-Lost_Illusion.git
cd ReconGO-by-Lost_Illusion
go build -o recongo ./cmd/recongo
./recongo -domain example.com
```

### go install

```bash
go install github.com/Lost-illusion69/recongo/cmd/recongo@latest
```

### Docker

```bash
docker build -t recongo .
docker run --rm recongo -domain example.com
```

---

## Usage

```
recongo -domain <target> [options]

Flags:
  -domain      string          Target domain to enumerate (required)
  -workers     int             Source-fetch concurrency  (default 50)
  -dns-workers int             DNS resolution concurrency (default 100)
  -timeout     duration        Per-lookup DNS timeout     (default 5s)
  -resolvers   string          Comma-separated DNS resolvers
                               e.g. "8.8.8.8:53,1.1.1.1:53"
  -verbose                     Enable debug-level logging
  -version                     Print version and exit
```

### Examples

```bash
# Basic enumeration
recongo -domain tesla.com

# Custom resolvers, higher concurrency, verbose
recongo -domain tesla.com \
  -resolvers "8.8.8.8:53,1.1.1.1:53" \
  -workers 100 \
  -dns-workers 200 \
  -verbose

# Pipe resolved hosts into other tools
recongo -domain tesla.com | awk '{print $2}' | httpx
```

---

## Configuration

All tunables are CLI flags — no config file or environment variable parsing is required. This keeps the binary self-contained and auditable.

| Flag | Default | Notes |
|---|---|---|
| `-workers` | `50` | Keep below open-file-descriptor limit |
| `-dns-workers` | `100` | Each worker holds one UDP socket |
| `-timeout` | `5s` | Increase for slow/flaky nameservers |
| `-resolvers` | *(system)* | Override with trusted public resolvers |

---

## Adding a New Source

1. Create `pkg/sources/<name>/<name>.go`
2. Implement the `sources.Source` interface:

```go
package crtsh

import "github.com/Lost-illusion69/recongo/pkg/sources"

type Source struct{}

func (s *Source) Name() string { return "crtsh" }

func (s *Source) Fetch(domain string) ([]sources.Result, error) {
    // HTTP call to crt.sh JSON API
    // Parse response, return []sources.Result
}
```

3. Register it in `cmd/recongo/main.go → registeredSources()`:

```go
func registeredSources() []sources.Source {
    return []sources.Source{
        &crtsh.Source{},
        // ...
    }
}
```

That's it. No changes to the engine or DNS layer.

---

## Docker

```bash
# Build
docker build -t recongo:latest .

# Run
docker run --rm recongo:latest -domain example.com -resolvers "1.1.1.1:53"

# Inspect the minimal image
docker image inspect recongo:latest | jq '.[0].Size'
```

The `scratch`-based image contains only:
- The statically compiled `recongo` binary
- TLS root certificates (for HTTPS API calls)

---

## CI / CD Pipeline

The GitHub Actions workflow (`.github/workflows/ci.yml`) runs on every push to `main` and every pull request:

| Job | What it does |
|---|---|
| **build-and-test** | Matrix build on Go 1.22 & 1.23, race detector enabled, `go mod tidy` check |
| **lint** | `golangci-lint` with `errcheck`, `staticcheck`, `revive`, `gofmt`, `goimports` |
| **docker-build** | Multi-stage Docker build smoke-test (no push) |

---

## 🛡️ Defensive Context (Blue Team)

> This section is written for **SOC analysts, threat hunters, and blue teamers** who may observe ReconGo (or similar tools) running against their infrastructure. Understanding attacker tooling is a core part of a mature defence posture.

### How ReconGo looks on the wire

| Observable | Signal |
|---|---|
| **High-frequency DNS queries** | A single source IP sends dozens–hundreds of `A`/`AAAA` queries per second, often to a non-corporate resolver (8.8.8.8, 1.1.1.1) |
| **Subdomain pattern** | Queries follow enumeration wordlists: `admin.`, `api.`, `dev.`, `staging.`, `mail.` prefixes in rapid succession |
| **Low TTL indifference** | The resolver ignores cached TTLs — the same FQDN may be queried multiple times in seconds |
| **No matching HTTP traffic** | DNS queries spike with no corresponding HTTP/S connections — indicating enumeration rather than browsing |
| **User-Agent absence** | API calls (crt.sh, HackerTarget) use Go's default UA (`Go-http-client/1.1`) unless overridden |
| **Certificate Transparency polling** | Queries to `crt.sh` or `api.hackertarget.com` for a single domain in bulk |

### SIEM Detection — Windows Event ID 22 (Sysmon DNS Query)

The following **Sigma rule** detects rapid DNS resolution attempts consistent with subdomain enumeration on Windows endpoints running Sysmon:

```yaml
title: Rapid DNS Resolution — Possible Subdomain Enumeration
id: a3f7c812-3e4d-4b9a-8f1c-7d2e6a0b5c9f
status: experimental
description: >
  Detects a high volume of DNS queries originating from a single process
  in a short time window, consistent with automated subdomain enumeration
  tools such as ReconGo, amass, subfinder, or gobuster DNS mode.
references:
  - https://github.com/Lost-illusion69/ReconGO-by-Lost_Illusion
  - https://attack.mitre.org/techniques/T1018/
  - https://attack.mitre.org/techniques/T1595/001/
author: Lost-illusion69
date: 2026-08-13
tags:
  - attack.reconnaissance
  - attack.t1595.001   # Active Scanning: Scanning IP Blocks
  - attack.t1018       # Remote System Discovery
logsource:
  product: windows
  category: dns_query          # Sysmon Event ID 22
detection:
  selection:
    EventID: 22
  timeframe: 10s
  condition: selection | count() by ProcessId, Image > 50
  # Fires when a single process emits more than 50 DNS queries in 10 seconds.
falsepositives:
  - Legitimate software updaters performing bulk CDN resolution
  - Browser pre-fetching on heavily-trafficked developer machines
  - Internal service-discovery tools (Consul, Kubernetes DNS)
level: medium
fields:
  - Image          # Full path of the querying process
  - QueryName      # The FQDN being resolved
  - QueryResults   # Returned IP address(es)
  - ProcessId
  - User
```

### Network-level detection (DNS / NDR)

```yaml
title: DNS Enumeration Burst — Single Source IP
id: b9e2d471-5c3a-4f8b-a02d-1e7f9c6b3d84
status: experimental
description: >
  More than 200 unique FQDN queries from a single RFC-1918 or external IP
  within 60 seconds against the corporate recursive resolver.
logsource:
  product: zeek
  service: dns
detection:
  selection:
    proto: udp
    qtype_name|contains:
      - "A"
      - "AAAA"
  timeframe: 60s
  condition: selection | count(query) by id.orig_h > 200
falsepositives:
  - CI/CD pipelines performing integration tests
  - Load balancers with health-check probes
level: high
fields:
  - id.orig_h    # Source IP
  - query        # Queried hostname
  - answers      # Resolved IPs
```

### Recommended mitigations

| Control | Implementation |
|---|---|
| **DNS rate limiting** | Configure recursive resolver (Unbound, BIND, Windows DNS) to rate-limit queries per source IP |
| **RPZ (Response Policy Zones)** | Block or redirect queries matching known enumeration patterns |
| **Passive DNS logging** | Enable full DNS query logging; alert on query volume anomalies |
| **Certificate Transparency monitoring** | Monitor crt.sh / Google CT logs for new certificates issued against your domain |
| **Ingress firewall** | Block outbound DNS to non-authorised resolvers (prevent use of 8.8.8.8 bypass) |

---

## Roadmap

- [ ] Real source integrations: crt.sh, HackerTarget, Alienvault OTX, VirusTotal
- [ ] JSON / CSV / NDJSON output formats
- [ ] stdin / file input for multi-domain scans
- [ ] HTTP probing stage (status codes, titles)
- [ ] Port scanning integration
- [ ] Config file support (YAML)
- [ ] Plugin system for custom sources

---

## License

MIT © 2026 [Lost-illusion69](https://github.com/Lost-illusion69)
