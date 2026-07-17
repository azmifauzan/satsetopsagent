package executor

import (
	"testing"

	"github.com/satsetops/agent/internal/exec"
)

func TestDockerHarden(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Outputs["mkdir -p /etc/docker"] = ""
	runner.Outputs["bash -c echo -e '{\\n  \"icc\": false,\\n  \"userns-remap\": \"default\",\\n  \"live-restore\": true,\\n  \"userland-proxy\": false,\\n  \"no-new-privileges\": true\\n}' > /etc/docker/daemon.json"] = ""
	runner.Outputs["systemctl restart docker"] = ""

	_, err := dockerHarden(nil, runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !runner.HasCommand("systemctl restart docker") {
		t.Errorf("expected docker restart command")
	}
}

func TestDockerHardenRetriesTransientRestartFailureThenSucceeds(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Outputs["mkdir -p /etc/docker"] = ""
	runner.Outputs["bash -c echo -e '{\n  \"icc\": false,\n  \"userns-remap\": \"default\",\n  \"live-restore\": true,\n  \"userland-proxy\": false,\n  \"no-new-privileges\": true\n}' > /etc/docker/daemon.json"] = ""
	runner.FailTimes["systemctl restart docker"] = 2
	runner.Outputs["systemctl restart docker"] = ""

	_, err := dockerHarden(nil, runner)
	if err != nil {
		t.Fatalf("expected the 3rd attempt to succeed, got error: %v", err)
	}
}
