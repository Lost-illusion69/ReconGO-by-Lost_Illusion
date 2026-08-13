package prober

import (
	"sync"
	"time"
)

const (
	maxProbeRetries = 4
	initialBackoff  = 500 * time.Millisecond
	maxBackoff      = 8 * time.Second
)

type hostBackoff struct {
	mu    sync.Mutex
	delay time.Duration
}

var backoffRegistry sync.Map // map[string]*hostBackoff

func waitForHost(host string) {
	state := getBackoff(host)
	state.mu.Lock()
	delay := state.delay
	state.mu.Unlock()
	if delay > 0 {
		time.Sleep(delay)
	}
}

func recordRateLimit(host string) time.Duration {
	state := getBackoff(host)
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.delay == 0 {
		state.delay = initialBackoff
	} else {
		state.delay *= 2
		if state.delay > maxBackoff {
			state.delay = maxBackoff
		}
	}
	return state.delay
}

func resetBackoff(host string) {
	if v, ok := backoffRegistry.Load(host); ok {
		v.(*hostBackoff).mu.Lock()
		v.(*hostBackoff).delay = 0
		v.(*hostBackoff).mu.Unlock()
	}
}

func getBackoff(host string) *hostBackoff {
	if v, ok := backoffRegistry.Load(host); ok {
		return v.(*hostBackoff)
	}
	state := &hostBackoff{}
	actual, _ := backoffRegistry.LoadOrStore(host, state)
	return actual.(*hostBackoff)
}

func shouldRetryStatus(code int) bool {
	return code == 429 || code == 503
}
