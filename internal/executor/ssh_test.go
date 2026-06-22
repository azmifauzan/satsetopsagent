package executor

import (
	"strings"
	"testing"

	"github.com/satsetops/agent/internal/exec"
)

func TestSshHarden(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Outputs["cat /root/.ssh/authorized_keys"] = "ssh-rsa AAAAB3NzaC1yc2E..."
	runner.Outputs["bash -c echo -e 'PermitRootLogin no\\nPasswordAuthentication no\\n' > /etc/ssh/sshd_config.d/99-satsetops-harden.conf"] = ""
	runner.Outputs["systemctl reload ssh"] = ""

	_, err := sshHarden(nil, runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !runner.HasCommand("systemctl reload ssh") {
		t.Errorf("expected reload ssh command")
	}
}

func TestSshHardenNoKeyGuard(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Outputs["cat /root/.ssh/authorized_keys"] = "no keys here"

	_, err := sshHarden(nil, runner)
	if err == nil {
		t.Fatal("expected error from guard when no key found")
	}
	if !strings.Contains(err.Error(), "guard failed") {
		t.Errorf("expected guard failed error, got: %v", err)
	}
}
