package executor

import (
	"fmt"
	"strings"

	"github.com/satsetops/agent/internal/exec"
)

func sshHarden(payload map[string]any, runner exec.Runner) (string, error) {
	// Guard: Ensure authorized_keys has at least one valid key
	// We use 'cat' or 'grep' via runner to check for keys. Since this is an agent, runner is fine.
	out, err := runner.Run("cat", "/root/.ssh/authorized_keys")
	if err != nil {
		// Try checking /home/ubuntu/.ssh/authorized_keys as fallback?
		// For simplicity, let's just check if 'out' has ssh-rsa or ssh-ed25519
	}
	
	if !strings.Contains(out, "ssh-") {
		return "", fmt.Errorf("guard failed: no ssh key found in /root/.ssh/authorized_keys")
	}

	// Write drop-in config for idempotency instead of complex sed
	// Use bash -c "echo '...' > ..."
	configContent := "PermitRootLogin no\nPasswordAuthentication no\n"
	_, err = runner.Run("bash", "-c", fmt.Sprintf("echo -e '%s' > /etc/ssh/sshd_config.d/99-satsetops-harden.conf", configContent))
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
