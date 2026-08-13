package main

import (
	"strings"
	"testing"
)

func TestParseFlagsRequiredDomain(t *testing.T) {
	cfg, err := parseFlags([]string{})
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if cfg.domain != "" {
		t.Errorf("domain should be empty when not provided")
	}
}

func TestParseFlagsArchiveOriginDefaults(t *testing.T) {
	cfg, err := parseFlags([]string{"-domain", "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.domain != "example.com" {
		t.Errorf("domain = %q", cfg.domain)
	}
	if !cfg.archive || !cfg.findOrigin || !cfg.takeover {
		t.Errorf("defaults: archive=%v findOrigin=%v takeover=%v", cfg.archive, cfg.findOrigin, cfg.takeover)
	}
	if !cfg.mutate || !cfg.cluster || !cfg.probe {
		t.Error("expected mutate/cluster/probe defaults true")
	}
}

func TestParseFlagsDisableArchive(t *testing.T) {
	cfg, err := parseFlags([]string{"-domain", "example.com", "-archive=false", "-find-origin=false"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.archive || cfg.findOrigin {
		t.Errorf("archive=%v findOrigin=%v", cfg.archive, cfg.findOrigin)
	}
}

func TestParseFlagsWebhooks(t *testing.T) {
	cfg, err := parseFlags([]string{
		"-domain", "example.com",
		"-slack-webhook", "https://hooks.slack.com/test",
		"-discord-webhook", "https://discord.com/api/webhooks/x",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.slackWebhook == "" || cfg.discordWebhook == "" {
		t.Errorf("webhooks not parsed: slack=%q discord=%q", cfg.slackWebhook, cfg.discordWebhook)
	}
}

func TestFormatSource(t *testing.T) {
	cases := map[string]string{
		"crtsh":        "crt.sh",
		"alienvault":   "AlienVault OTX",
		"hackertarget": "HackerTarget",
		"wordlist":     "Wordlist",
		"archive":      "Archive",
		"custom-src":   "custom-src",
	}
	for in, want := range cases {
		if got := formatSource(in); got != want {
			t.Errorf("formatSource(%q) = %q want %q", in, got, want)
		}
	}
}

func TestFormatSourceCaseInsensitive(t *testing.T) {
	if got := formatSource("CRT.SH"); got != "crt.sh" {
		t.Errorf("got %q", got)
	}
}

func TestParseFlagsUnknown(t *testing.T) {
	_, err := parseFlags([]string{"-domain", "example.com", "-not-a-flag", "x"})
	if err == nil {
		t.Fatal("expected error for unknown flag")
	}
	if !strings.Contains(err.Error(), "not defined") {
		t.Errorf("error = %v", err)
	}
}
