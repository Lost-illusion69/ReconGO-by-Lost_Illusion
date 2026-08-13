// Package clustering assigns cluster tags to probed assets by MMH3 similarity.
package clustering

import (
	"fmt"
	"sync"

	"github.com/Lost-illusion69/recongo/models"
)

// Assigner groups hosts sharing favicon or body MMH3 hashes.
type Assigner struct {
	mu sync.Mutex
	// key "fav:<hash>" or "body:<hash>" -> cluster tag
	clusters map[string]string
}

// New creates a cluster tag assigner.
func New() *Assigner {
	return &Assigner{clusters: make(map[string]string)}
}

// Tag sets ClusterTag on r based on favicon or body hash groups.
func (a *Assigner) Tag(r *models.Result) {
	if r == nil {
		return
	}

	key, prefix := clusterKey(r)
	if key == "" {
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	tag, ok := a.clusters[key]
	if !ok {
		tag = fmt.Sprintf("%s-%d", prefix, len(a.clusters)+1)
		a.clusters[key] = tag
	}
	r.ClusterTag = tag
}

func clusterKey(r *models.Result) (key, prefix string) {
	if r.FaviconMMH3 != 0 {
		return fmt.Sprintf("fav:%d", r.FaviconMMH3), "favicon"
	}
	if r.BodyMMH3 != 0 {
		return fmt.Sprintf("body:%d", r.BodyMMH3), "body"
	}
	return "", ""
}

// TagAll assigns cluster tags to a slice of results.
func (a *Assigner) TagAll(results []*models.Result) {
	for _, r := range results {
		a.Tag(r)
	}
}

// TagBatch drains results from in, assigns tags, and forwards to out.
func (a *Assigner) TagBatch(results []models.Result) []models.Result {
	out := make([]models.Result, len(results))
	for i := range results {
		out[i] = results[i]
		a.Tag(&out[i])
	}
	return out
}
