package clustering

import (
	"testing"

	"github.com/Lost-illusion69/recongo/models"
)

func TestAssignSameFaviconCluster(t *testing.T) {
	a := New()
	r1 := &models.Result{Host: "a.example.com", FaviconMMH3: 12345}
	r2 := &models.Result{Host: "b.example.com", FaviconMMH3: 12345}
	r3 := &models.Result{Host: "c.example.com", FaviconMMH3: 99999}

	a.Tag(r1)
	a.Tag(r2)
	a.Tag(r3)

	if r1.ClusterTag == "" || r2.ClusterTag == "" || r3.ClusterTag == "" {
		t.Fatal("expected cluster tags")
	}
	if r1.ClusterTag != r2.ClusterTag {
		t.Errorf("same favicon hash should share cluster: %q vs %q", r1.ClusterTag, r2.ClusterTag)
	}
	if r1.ClusterTag == r3.ClusterTag {
		t.Error("different hash should not share cluster")
	}
}

func TestBodyHashFallback(t *testing.T) {
	a := New()
	r := &models.Result{Host: "x.example.com", BodyMMH3: 42}
	a.Tag(r)
	if r.ClusterTag == "" {
		t.Fatal("expected body cluster tag")
	}
	if r.ClusterTag[:5] != "body-" {
		t.Errorf("ClusterTag = %q, want body- prefix", r.ClusterTag)
	}
}
