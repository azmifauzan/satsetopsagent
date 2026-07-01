package executor

import (
	"testing"

	"github.com/satsetops/agent/internal/exec"
)

func TestUnknownTypeReturnsError(t *testing.T) {
	runner := exec.NewFakeRunner()
	if _, err := Dispatch("totally_unknown", nil, runner); err == nil {
		t.Fatal("expected error for unknown command type")
	}
}

// unsupported types must stay rejected — a
// fake "success" stub would lie to the orchestrator about work being done.
func TestPhase3PlusTypesRejected(t *testing.T) {
	runner := exec.NewFakeRunner()
	for _, commandType := range []string{
		"totally_future_command",
	} {
		if _, err := Dispatch(commandType, nil, runner); err == nil {
			t.Errorf("expected %q to be rejected as unimplemented", commandType)
		}
	}
}
