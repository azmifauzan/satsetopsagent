package executor

import (
	"strings"
	"testing"

	"github.com/satsetops/agent/internal/exec"
)

func TestSshHarden(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Outputs["bash -c echo -e 'PermitEmptyPasswords no\\nMaxAuthTries 4\\nX11Forwarding no\\n' > /etc/ssh/sshd_config.d/99-satsetops-harden.conf"] = ""
	runner.Outputs["systemctl reload ssh"] = ""

	_, err := sshHarden(nil, runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !runner.HasCommand("systemctl reload ssh") {
		t.Errorf("expected reload ssh command")
	}
}

func TestSshHardenDoesNotTouchLoginMethod(t *testing.T) {
	runner := exec.NewFakeRunner()

	if _, err := sshHarden(nil, runner); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, cmd := range runner.Commands {
		if strings.Contains(cmd, "PermitRootLogin") || strings.Contains(cmd, "PasswordAuthentication no") {
			t.Fatalf("ssh_harden must never touch root login or password auth, got command: %s", cmd)
		}
	}
}
