package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSendSlackEmptyURL(t *testing.T) {
	if err := SendSlack(context.Background(), "", Summary{Domain: "example.com"}); err != nil {
		t.Fatalf("empty URL should no-op: %v", err)
	}
}

func TestSendDiscordEmptyURL(t *testing.T) {
	if err := SendDiscord(context.Background(), "  ", Summary{}); err != nil {
		t.Fatalf("blank URL should no-op: %v", err)
	}
}

func TestSendSlackPayload(t *testing.T) {
	var body map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); !strings.Contains(ct, "application/json") {
			t.Errorf("content-type = %q", ct)
		}
		data, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(data, &body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := Summary{Domain: "example.com", Probed: 10, Endpoints: 3, Mutations: 5}
	if err := SendSlack(context.Background(), srv.URL, s); err != nil {
		t.Fatalf("SendSlack: %v", err)
	}
	if !strings.Contains(body["text"], "example.com") {
		t.Errorf("payload text = %q", body["text"])
	}
	if !strings.Contains(body["text"], "Probed: 10") {
		t.Errorf("missing probed count: %q", body["text"])
	}
}

func TestSendDiscordPayload(t *testing.T) {
	var body map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(data, &body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if err := SendDiscord(context.Background(), srv.URL, Summary{Domain: "target.com", Probed: 1}); err != nil {
		t.Fatalf("SendDiscord: %v", err)
	}
	if !strings.Contains(body["content"], "target.com") {
		t.Errorf("content = %q", body["content"])
	}
}

func TestPostWebhookErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	err := post(context.Background(), srv.URL, []byte(`{"text":"x"}`))
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Errorf("expected 500 error, got %v", err)
	}
}

func TestSummaryFields(t *testing.T) {
	s := Summary{Domain: "a.com", Probed: 2, Endpoints: 1, Mutations: 3}
	if s.Domain != "a.com" || s.Probed != 2 || s.Endpoints != 1 || s.Mutations != 3 {
		t.Errorf("Summary fields not set: %+v", s)
	}
}
