package main

import (
	"testing"
	"time"
)

func TestStageOneRejectsUnknownProfile(t *testing.T) {
	err := execute(&result{}, "https://localhost:8443", "", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"chrome_149", time.Second)
	if err == nil || err.Error() != "stage 1 requires the pinned chrome_150 profile" {
		t.Fatalf("unexpected result: %v", err)
	}
}

func TestStageOneRejectsNonLoopbackOrigin(t *testing.T) {
	err := execute(&result{}, "https://example.com", "", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"chrome_150", time.Second)
	if err == nil || err.Error() != "origin host must be loopback" {
		t.Fatalf("unexpected result: %v", err)
	}
}

func TestStageOneRejectsMalformedSession(t *testing.T) {
	err := execute(&result{}, "https://localhost:8443", "", "invalid",
		"chrome_150", time.Second)
	if err == nil || err.Error() != "invalid session or deadline" {
		t.Fatalf("unexpected result: %v", err)
	}
}

func TestNormalizeProtocol(t *testing.T) {
	if got := normalizeProtocol("HTTP/2.0"); got != "h2" {
		t.Fatalf("got %q, want h2", got)
	}
	if got := normalizeProtocol("HTTP/1.1"); got != "http/1.1" {
		t.Fatalf("got %q, want http/1.1", got)
	}
}
