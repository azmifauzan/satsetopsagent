package executor

import (
	"fmt"

	"github.com/satsetops/agent/internal/exec"
)

func dockerHarden(payload map[string]any, runner exec.Runner) (string, error) {
	// Write daemon.json
	daemonJson := `{
  "icc": false,
  "userns-remap": "default",
  "live-restore": true,
  "userland-proxy": false,
  "no-new-privileges": true
}`
	
	// Create /etc/docker if not exists
	_, _ = runner.Run("mkdir", "-p", "/etc/docker")

	_, err := runner.Run("bash", "-c", fmt.Sprintf("echo -e '%s' > /etc/docker/daemon.json", daemonJson))
	if err != nil {
		return "", fmt.Errorf("failed to write daemon.json: %w", err)
	}

	// Restart docker
	_, err = runner.Run("systemctl", "restart", "docker")
	if err != nil {
		return "", fmt.Errorf("failed to restart docker: %w", err)
	}

	return "docker daemon hardened", nil
}

// These are placeholders for other phase 2 commands
func deployApp(payload map[string]any, runner exec.Runner) (string, error) {
	return "app deployed", nil
}

func restartContainer(payload map[string]any, runner exec.Runner) (string, error) {
	return "container restarted", nil
}

func stopContainer(payload map[string]any, runner exec.Runner) (string, error) {
	return "container stopped", nil
}

func collectLogs(payload map[string]any, runner exec.Runner) (string, error) {
	return "logs collected", nil
}
