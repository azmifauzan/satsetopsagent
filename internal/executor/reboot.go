package executor

import (
	"fmt"

	"github.com/satsetops/agent/internal/exec"
)

func rebootServer(runner exec.Runner) (string, error) {
	if _, err := runner.Run("systemctl", "reboot"); err == nil {
		return `{"reboot_requested":true}`, nil
	}

	if _, err := runner.Run("shutdown", "-r", "now"); err != nil {
		return "", fmt.Errorf("request reboot: %w", err)
	}
	return `{"reboot_requested":true}`, nil
}
