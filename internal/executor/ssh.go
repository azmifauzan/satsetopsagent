package executor

import (
	"fmt"

	"github.com/satsetops/agent/internal/exec"
)

// sshHarden intentionally never touches PermitRootLogin or PasswordAuthentication:
// many small Indonesian VPSes are provisioned with only a root+password account
// and no other login path, so disabling either would permanently lock the user
// out of their own VPS. Hardening here is limited to settings that reduce
// brute-force/attack surface without changing how anyone logs in.
func sshHarden(payload map[string]any, runner exec.Runner) (string, error) {
	configContent := "PermitEmptyPasswords no\nMaxAuthTries 4\nX11Forwarding no\n"
	_, err := runner.Run("bash", "-c", fmt.Sprintf("echo -e '%s' > /etc/ssh/sshd_config.d/99-satsetops-harden.conf", configContent))
	if err != nil {
		return "", fmt.Errorf("failed to write sshd_config.d: %w", err)
	}

	// Reload sshd
	// On ubuntu, it's ssh. On some it's sshd.
	_, err = runner.Run("systemctl", "reload", "ssh")
	if err != nil {
		// Fallback to sshd
		_, err = runner.Run("systemctl", "reload", "sshd")
		if err != nil {
			return "", fmt.Errorf("failed to reload ssh service: %w", err)
		}
	}

	return "ssh hardened", nil
}
