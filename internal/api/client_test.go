package api

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRegisterReturnsPermanentToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/agent/register" || r.Method != http.MethodPost {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"permanent_token":"perm-123"}`))
	}))
	defer server.Close()

	token, err := New(server.URL, "").Register("one-time")
	if err != nil || token != "perm-123" {
		t.Fatalf("got %q, err %v", token, err)
	}
}

func TestPostMetricsParsesIntervalHint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/agent/metrics" || r.Method != http.MethodPost {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"ok":true,"metrics_enabled":false,"next_interval_seconds":3600}`))
	}))
	defer server.Close()

	response, err := New(server.URL, "perm-123").PostMetrics(Metrics{})
	if err != nil {
		t.Fatalf("PostMetrics: %v", err)
	}
	if response.MetricsEnabled || response.NextIntervalSeconds != 3600 {
		t.Fatalf("unexpected response: %+v", response)
	}
}

func TestPollUsesBearerAndReturnsCommands(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer perm-123" {
			t.Fatalf("unexpected authorization header %q", r.Header.Get("Authorization"))
		}
		_, _ = w.Write([]byte(`[{"id":1,"type":"scan_vps","payload":null}]`))
	}))
	defer server.Close()

	commands, err := New(server.URL, "perm-123").Poll()
	if err != nil || len(commands) != 1 || commands[0].Type != "scan_vps" {
		t.Fatalf("commands %+v, err %v", commands, err)
	}
}

func TestPollReturnsUnauthorizedSentinel(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	_, err := New(server.URL, "revoked").Poll()
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("want ErrUnauthorized, got %v", err)
	}
}
