// Package models defines shared data types for the ReconGo pipeline.
package models

import "time"

// Result holds the outcome of a successful HTTP probe against a host.
type Result struct {
	Host          string        `json:"host"`
	IPs           []string      `json:"ips"`
	URL           string        `json:"url"`
	StatusCode    int           `json:"status_code"`
	Title         string        `json:"title"`
	Server        string        `json:"server"`
	ContentLength int64         `json:"content_length"`
	ResponseTime  time.Duration `json:"response_time_ns"`
	FaviconMMH3   int32         `json:"favicon_mmh3,omitempty" csv:"favicon_mmh3"`
	BodyMMH3      int32         `json:"body_mmh3,omitempty" csv:"body_mmh3"`
	ClusterTag    string        `json:"cluster_tag,omitempty" csv:"cluster_tag"`
	Endpoints     []string      `json:"endpoints,omitempty" csv:"endpoints"`
}
