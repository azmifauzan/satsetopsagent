package executor

import (
	"errors"
	"testing"

	"github.com/satsetops/agent/internal/exec"
)

func TestRebootServerFallback(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Errors["systemctl reboot"] = errors.New("missing systemd")

	if _, err := Dispatch("reboot_server", nil, runner); err != nil {
		t.Fatalf("reboot_server: %v", err)
	}
	if !runner.HasCommand("shutdown -r now") {
		t.Fatalf("expected shutdown fallback, got %#v", runner.Commands)
	}
}
