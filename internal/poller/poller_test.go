package poller

import (
	"errors"
	"testing"

	"github.com/satsetops/agent/internal/api"
)

type fakeClient struct {
	commands []api.Command
	pollErr  error
	results  int
	success  bool
}

func (f *fakeClient) Poll() ([]api.Command, error) {
	return f.commands, f.pollErr
}

func (f *fakeClient) PostResult(_ int, success bool, _ string, _ int) error {
	f.results++
	f.success = success
	return nil
}

func (f *fakeClient) PostMetrics(api.Metrics) error { return nil }

func TestRunOnceStopsOnUnauthorized(t *testing.T) {
	client := &fakeClient{pollErr: api.ErrUnauthorized}
	if err := RunOnce(client); !errors.Is(err, api.ErrUnauthorized) {
		t.Fatalf("want ErrUnauthorized, got %v", err)
	}
}

func TestRunOnceExecutesCommandAndPostsResult(t *testing.T) {
	client := &fakeClient{commands: []api.Command{{ID: 1, Type: "scan_vps"}}}
	if err := RunOnce(client); err != nil {
		t.Fatalf("run once: %v", err)
	}
	if client.results != 1 || !client.success {
		t.Fatalf("results %d, success %v", client.results, client.success)
	}
}

func TestRunOnceReportsRejectedCommandAsFailure(t *testing.T) {
	client := &fakeClient{commands: []api.Command{{ID: 1, Type: "shell"}}}
	if err := RunOnce(client); err != nil {
		t.Fatalf("run once: %v", err)
	}
	if client.results != 1 || client.success {
		t.Fatalf("results %d, success %v", client.results, client.success)
	}
}
