package executor

import (
	"fmt"

	"github.com/satsetops/agent/internal/exec"
)

func sysupdateHarden(payload map[string]any, runner exec.Runner) (string, error) {
	// Install unattended-upgrades. DEBIAN_FRONTEND=noninteractive is required:
	// apt-get otherwise tries a debconf dialog and fails outright under
	// systemd, which gives the process no controlling TTY.
	_, err := runner.Run("bash", "-c", "DEBIAN_FRONTEND=noninteractive apt-get install -y unattended-upgrades")
	if err != nil {
		return "", fmt.Errorf("failed to install unattended-upgrades: %w", err)
	}

	// Write config for security only
	config := `Unattended-Upgrade::Allowed-Origins {
	"${distro_id}:${distro_codename}-security";
	// Extended Security Maintenance (ESM)
	"${distro_id}ESMApps:${distro_codename}-apps-security";
	"${distro_id}ESM:${distro_codename}-infra-security";
};
Unattended-Upgrade::Package-Blacklist {
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::InstallOnShutdown "false";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
`
	_, err = runner.Run("bash", "-c", fmt.Sprintf("echo -e '%s' > /etc/apt/apt.conf.d/50unattended-upgrades", config))
	if err != nil {
		return "", fmt.Errorf("failed to write unattended-upgrades config: %w", err)
	}

	// Enable it
	enableConfig := `APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
`
	_, err = runner.Run("bash", "-c", fmt.Sprintf("echo -e '%s' > /etc/apt/apt.conf.d/20auto-upgrades", enableConfig))
	if err != nil {
		return "", fmt.Errorf("failed to enable auto-upgrades: %w", err)
	}

	// Restart service just in case
	_, err = runner.Run("systemctl", "restart", "unattended-upgrades")
	if err != nil {
		// some OS might not have it as a service but a cron
	}

	return "unattended-upgrades configured for security", nil
}
