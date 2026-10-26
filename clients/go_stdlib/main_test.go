package main

import (
	"strings"
	"testing"
	"time"
)

func TestExecuteRejectsInvalidSessionBeforeNetworkAccess(t *testing.T) {
	out := result{}
	err := execute(&out, "https://localhost:8443", "missing-ca.pem", "not-a-session", time.Second)
	if err == nil || !strings.Contains(err.Error(), "invalid session") {
		t.Fatalf("expected invalid-session error, got %v", err)
	}
}

func TestExecuteRejectsNonLoopbackOrigin(t *testing.T) {
	out := result{}
	err := execute(&out, "https://example.com", "missing-ca.pem", strings.Repeat("a", 32), time.Second)
	if err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("expected loopback error, got %v", err)
	}
}

func TestNormalizedProtocol(t *testing.T) {
	tests := map[string]string{
		"HTTP/2.0": "h2",
		"HTTP/1.1": "http/1.1",
		"HTTP/3.0": "http/3.0",
	}
	for input, expected := range tests {
		if actual := normalizedProtocol(input); actual != expected {
			t.Errorf("normalizedProtocol(%q) = %q, want %q", input, actual, expected)
		}
	}
}
