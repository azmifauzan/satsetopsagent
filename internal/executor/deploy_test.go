package executor

import (
	"errors"
	"testing"

	"github.com/satsetops/agent/internal/exec"
)

func TestDeployApp(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Outputs["docker pull test-image:latest"] = ""
	runner.Outputs["docker rm -f test-app"] = ""
	runner.Outputs["docker run -d --name test-app -p 127.0.0.1:8080:8080 --restart unless-stopped -e FOO=BAR test-image:latest"] = "container_id_12345"

	payload := map[string]any{
		"image": "test-image:latest",
		"name":  "test-app",
		"port":  8080,
		"env": map[string]any{
			"FOO": "BAR",
		},
	}

	containerID, err := deployApp(payload, runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if containerID != "container_id_12345" {
		t.Errorf("expected container id container_id_12345, got %s", containerID)
	}

	if !runner.HasCommand("docker pull test-image:latest") {
		t.Errorf("missing docker pull command")
	}

	if !runner.HasCommand("docker rm -f test-app") {
		t.Errorf("missing docker rm command")
	}
}

func TestDeployAppPullError(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Errors["docker pull test-image:latest"] = errors.New("pull failed")

	payload := map[string]any{
		"image": "test-image:latest",
		"name":  "test-app",
		"port":  "8080",
	}

	_, err := deployApp(payload, runner)
	if err == nil {
		t.Fatal("expected error on pull failure, got nil")
	}
}

func TestContainerControl(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Outputs["docker restart test-app"] = ""
	runner.Outputs["docker stop test-app"] = ""

	payload := map[string]any{
		"name": "test-app",
	}

	_, err := restartContainer(payload, runner)
	if err != nil {
		t.Fatalf("unexpected restart error: %v", err)
	}

	if !runner.HasCommand("docker restart test-app") {
		t.Errorf("missing docker restart command")
	}

	_, err = stopContainer(payload, runner)
	if err != nil {
		t.Fatalf("unexpected stop error: %v", err)
	}

	if !runner.HasCommand("docker stop test-app") {
		t.Errorf("missing docker stop command")
	}
}
