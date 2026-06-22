package executor

import (
	"testing"

	"github.com/satsetops/agent/internal/exec"
)

func TestCollectLogs(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Outputs["docker logs --tail 50 test-app"] = "log-line-1\nlog-line-2"

	payload := map[string]any{
		"name": "test-app",
		"tail": 50,
	}

	logs, err := collectLogs(payload, runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if logs != "log-line-1\nlog-line-2" {
		t.Errorf("expected logs text, got %s", logs)
	}

	if !runner.HasCommand("docker logs --tail 50 test-app") {
		t.Errorf("expected docker logs command")
	}
}
