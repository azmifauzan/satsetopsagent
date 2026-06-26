package reporter

import (
	"errors"
	"testing"
)

type fakeRunner struct {
	runFunc func(cmd string, args ...string) (string, error)
}

func (f *fakeRunner) Run(cmd string, args ...string) (string, error) {
	return f.runFunc(cmd, args...)
}

func (f *fakeRunner) RunWithStdin(cmd string, stdin string, args ...string) (string, error) {
	return f.runFunc(cmd, args...)
}

func TestCollectTraffic_Success(t *testing.T) {
	fakeLogs := `127.0.0.1 - - [26/Jun/2026:16:00:00 +0700] "GET /index.html HTTP/1.1" 200 1000 "-" "Mozilla"
192.168.1.5 - - [26/Jun/2026:16:00:05 +0700] "POST /api/login?ref=test HTTP/1.1" 401 250 "-" "Mozilla"
127.0.0.1 - - [26/Jun/2026:16:00:10 +0700] "GET /index.html HTTP/1.1" 200 1000 "-" "Mozilla"
8.8.8.8 - - [26/Jun/2026:16:00:15 +0700] "GET /badpath HTTP/1.1" 404 150 "-" "Mozilla"
10.0.0.1 - - [26/Jun/2026:16:00:20 +0700] "GET /error HTTP/1.1" 500 500 "-" "Mozilla"
192.168.1.5 - - [26/Jun/2026:16:00:25 +0700] "POST /api/login?ref=test HTTP/1.1" 401 250 "-" "Mozilla"
127.0.0.1 - - [26/Jun/2026:16:00:30 +0700] "GET /index.html HTTP/1.1" 200 1000 "-" "Mozilla"
`
	runner := &fakeRunner{
		runFunc: func(cmd string, args ...string) (string, error) {
			if cmd == "tail" && args[2] == "/var/log/nginx/access.log" {
				return fakeLogs, nil
			}
			return "", errors.New("unexpected command")
		},
	}

	summary, err := CollectTraffic(runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if summary.TotalRequests != 7 {
		t.Errorf("expected 7 requests, got %d", summary.TotalRequests)
	}
	if summary.Requests4xx != 3 { // two 401, one 404
		t.Errorf("expected 3 4xx requests, got %d", summary.Requests4xx)
	}
	if summary.Requests5xx != 1 { // 500
		t.Errorf("expected 1 5xx request, got %d", summary.Requests5xx)
	}
	if summary.BandwidthBytes != 4150 { // 1000 + 250 + 1000 + 150 + 500 + 250 + 1000
		t.Errorf("expected 4150 bytes, got %d", summary.BandwidthBytes)
	}

	// Verify top paths (query parameters stripped)
	if len(summary.TopPaths) < 2 {
		t.Fatalf("expected at least 2 top paths, got %d", len(summary.TopPaths))
	}
	if summary.TopPaths[0].Path != "/index.html" || summary.TopPaths[0].Count != 3 {
		t.Errorf("expected top path /index.html with count 3, got %+v", summary.TopPaths[0])
	}
	if summary.TopPaths[1].Path != "/api/login" || summary.TopPaths[1].Count != 2 {
		t.Errorf("expected second path /api/login with count 2, got %+v", summary.TopPaths[1])
	}

	// Verify top IPs
	if len(summary.TopIPs) < 2 {
		t.Fatalf("expected at least 2 top IPs, got %d", len(summary.TopIPs))
	}
	if summary.TopIPs[0].IP != "127.0.0.1" || summary.TopIPs[0].Count != 3 {
		t.Errorf("expected top IP 127.0.0.1 with count 3, got %+v", summary.TopIPs[0])
	}
	if summary.TopIPs[1].IP != "192.168.1.5" || summary.TopIPs[1].Count != 2 {
		t.Errorf("expected second IP 192.168.1.5 with count 2, got %+v", summary.TopIPs[1])
	}
}

func TestCollectTraffic_Fallback(t *testing.T) {
	runner := &fakeRunner{
		runFunc: func(cmd string, args ...string) (string, error) {
			if cmd == "tail" {
				return "", errors.New("log not found")
			}
			if cmd == "docker" && args[0] == "logs" && args[3] == "nginx-certbot" {
				return `127.0.0.1 - - [26/Jun/2026:16:00:00] "GET / HTTP/1.1" 200 100`, nil
			}
			return "", errors.New("unexpected command")
		},
	}

	summary, err := CollectTraffic(runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if summary.TotalRequests != 1 {
		t.Errorf("expected 1 request, got %d", summary.TotalRequests)
	}
}
