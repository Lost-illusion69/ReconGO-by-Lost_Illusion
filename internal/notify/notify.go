// Package notify sends scan summary alerts to Slack and Discord webhooks.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Summary holds scan completion stats for webhook payloads.
type Summary struct {
	Domain    string
	Probed    int64
	Endpoints int
	Mutations int64
}

// SendSlack posts a JSON payload to a Slack incoming webhook URL.
func SendSlack(ctx context.Context, webhookURL string, s Summary) error {
	webhookURL = strings.TrimSpace(webhookURL)
	if webhookURL == "" {
		return nil
	}
	text := fmt.Sprintf("ReconGO scan complete for *%s*\nProbed: %d | Endpoints: %d | Mutations: %d",
		s.Domain, s.Probed, s.Endpoints, s.Mutations)
	body, _ := json.Marshal(map[string]string{"text": text})
	return post(ctx, webhookURL, body)
}

// SendDiscord posts a JSON payload to a Discord webhook URL.
func SendDiscord(ctx context.Context, webhookURL string, s Summary) error {
	webhookURL = strings.TrimSpace(webhookURL)
	if webhookURL == "" {
		return nil
	}
	content := fmt.Sprintf("ReconGO scan complete for **%s** — probed: %d, endpoints: %d, mutations: %d",
		s.Domain, s.Probed, s.Endpoints, s.Mutations)
	body, _ := json.Marshal(map[string]string{"content": content})
	return post(ctx, webhookURL, body)
}

func post(ctx context.Context, url string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook status %d", resp.StatusCode)
	}
	return nil
}
