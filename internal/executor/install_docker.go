package executor

import (
	"fmt"
	"time"

	"github.com/satsetops/agent/internal/distro"
	"github.com/satsetops/agent/internal/exec"
)

// installDocker runs once, only when scan_vps reported no Docker on the
// VPS. Native per-distro packages, deliberately not Docker's own
// get.docker.com convenience script — every other executor in this agent
// uses distro-native tooling, never curl|sh from a third party.
func installDocker(runner exec.Runner) (string, error) {
	if distro.CommandExists(runner, "docker") {
		return "docker already installed", nil
	}

	family, err := distro.Detect(runner)
	if err != nil {
		return "", fmt.Errorf("detect distro: %w", err)
	}

	switch family {
	case distro.RHEL:
		manager := "dnf"
		plugin := "dnf-plugins-core"
		configManager := "dnf config-manager"
		if !distro.CommandExists(runner, "dnf") {
			manager = "yum"
			plugin = "yum-utils"
			configManager = "yum-config-manager"
		}

		// docker-ce isn't in the stock BaseOS/AppStream repos — Docker's
		// own repo has to be added first, same as install_crowdsec adds
		// its repo before installing the crowdsec package.
		if _, err := withRetry(3, 10*time.Second, func() (string, error) {
			return runner.Run("bash", "-c", manager+" install -y "+plugin)
		}); err != nil {
			return "", fmt.Errorf("failed to install %s: %w", plugin, err)
		}
		if _, err := withRetry(3, 10*time.Second, func() (string, error) {
			return runner.Run("bash", "-c", configManager+" --add-repo https://download.docker.com/linux/centos/docker-ce.repo")
		}); err != nil {
			return "", fmt.Errorf("failed to add docker-ce repo: %w", err)
		}
		if _, err := withRetry(3, 10*time.Second, func() (string, error) {
			return runner.Run("bash", "-c", manager+" install -y docker-ce docker-ce-cli containerd.io")
		}); err != nil {
			return "", fmt.Errorf("failed to install docker (%s): %w", manager, err)
		}
	case distro.Arch:
		if _, err := withRetry(3, 10*time.Second, func() (string, error) {
			return runner.Run("bash", "-c", "pacman -Sy --noconfirm docker")
		}); err != nil {
			return "", fmt.Errorf("failed to pacman -S docker: %w", err)
		}
	default: // Debian and Unknown fall back to apt's docker.io package.
		if _, err := withRetry(3, 10*time.Second, func() (string, error) {
			return runner.Run("bash", "-c", "DEBIAN_FRONTEND=noninteractive apt-get install -y docker.io")
		}); err != nil {
			return "", fmt.Errorf("failed to apt-get install docker.io: %w", err)
		}
	}

	if _, err := runner.Run("systemctl", "enable", "--now", "docker"); err != nil {
		return "", fmt.Errorf("failed to start docker: %w", err)
	}

	return "docker installed", nil
}
