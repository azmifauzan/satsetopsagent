package exec_test

import (
	"errors"
	"strings"
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

func TestRealRunnerSurfacesStderr(t *testing.T) {
	runner := &exec.RealRunner{}

	_, err := runner.Run("sh", "-c", "echo 'boom' >&2; exit 1")
	if err == nil {
		t.Fatal("expected error from non-zero exit")
	}
	if !strings.Contains(err.Error(), "boom") {
		t.Fatalf("expected error to include stderr text, got: %v", err)
	}
}
