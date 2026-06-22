package exec_test

import (
	"errors"
	"testing"

	"github.com/satsetops/agent/internal/exec"
)

func TestFakeRunner(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Outputs["echo hello"] = "hello"
	runner.Errors["fail"] = errors.New("failed")

	out, err := runner.Run("echo", "hello")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out != "hello" {
		t.Fatalf("expected 'hello', got '%s'", out)
	}

	_, err = runner.Run("fail")
	if err == nil || err.Error() != "failed" {
		t.Fatalf("expected 'failed' error, got %v", err)
	}

	if !runner.HasCommand("echo hello") {
		t.Fatal("expected 'echo hello' to be recorded")
	}
}
