package executor

import (
	"encoding/json"
	"fmt"

	"github.com/satsetops/agent/internal/distro"
	"github.com/satsetops/agent/internal/exec"
)

func sysupdateHarden(payload map[string]any, runner exec.Runner) (string, error) {
	family, err := distro.Detect(runner)
	if err != nil {
		return "", fmt.Errorf("detect distro: %w", err)
	}

	switch family {
	case distro.Arch:
		// Deliberately unsupported: the Arch community explicitly advises
		// against automating `pacman -Syu` (partial upgrades can break a
		// system in ways a security-only apt/dnf policy never risks). The
		// one-time apt_upgrade equivalent still runs pacman once at
		// onboarding (see apt_upgrade.go) — this is only about the
		// *recurring* auto-upgrade daemon.
		return encodeSysupdateResult(false, true, false)
	case distro.RHEL:
		if err := configureRHELAutomaticUpdates(runner); err != nil {
			return "", err
		}
	default:
		if err := configureDebianUnattendedUpgrades(runner); err != nil {
			return "", err
		}
	}

	_, rebootErr := runner.Run("test", "-f", "/var/run/reboot-required")
	return encodeSysupdateResult(true, false, rebootErr == nil)
}

func configureDebianUnattendedUpgrades(runner exec.Runner) error {
	// Install unattended-upgrades. DEBIAN_FRONTEND=noninteractive is required:
	// apt-get otherwise tries a debconf dialog and fails outright under
	// systemd, which gives the process no controlling TTY.
	if _, err := runner.Run("bash", "-c", "DEBIAN_FRONTEND=noninteractive apt-get install -y unattended-upgrades"); err != nil {
		return fmt.Errorf("failed to install unattended-upgrades: %w", err)
	}

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
	if _, err := runner.Run("bash", "-c", fmt.Sprintf("echo -e '%s' > /etc/apt/apt.conf.d/50unattended-upgrades", config)); err != nil {
		return fmt.Errorf("failed to write unattended-upgrades config: %w", err)
	}

	enableConfig := `APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
`
	if _, err := runner.Run("bash", "-c", fmt.Sprintf("echo -e '%s' > /etc/apt/apt.conf.d/20auto-upgrades", enableConfig)); err != nil {
		return fmt.Errorf("failed to enable auto-upgrades: %w", err)
	}

	// Restart service just in case; some images might not have it as a
	// service yet on first install, so a failure here isn't fatal.
	_, _ = runner.Run("systemctl", "restart", "unattended-upgrades")

	return nil
}

func configureRHELAutomaticUpdates(runner exec.Runner) error {
	if _, err := runner.Run("bash", "-c", "dnf install -y dnf-automatic"); err != nil {
		return fmt.Errorf("failed to install dnf-automatic: %w", err)
	}

	config := `apply_updates = yes
upgrade_type = security
`
	if _, err := runner.Run("bash", "-c", fmt.Sprintf("echo -e '%s' > /etc/dnf/automatic.conf", config)); err != nil {
		return fmt.Errorf("failed to write dnf-automatic config: %w", err)
	}

	if _, err := runner.Run("systemctl", "enable", "--now", "dnf-automatic.timer"); err != nil {
		return fmt.Errorf("failed to enable dnf-automatic.timer: %w", err)
	}

	return nil
}

func encodeSysupdateResult(configured, skipped, rebootRequired bool) (string, error) {
	output := struct {
		SecurityUpdatesConfigured bool `json:"security_updates_configured"`
		Skipped                   bool `json:"skipped"`
		Changed                   bool `json:"changed"`
		RebootRequired            bool `json:"reboot_required"`
	}{
		SecurityUpdatesConfigured: configured,
		Skipped:                   skipped,
		Changed:                   configured,
		RebootRequired:            rebootRequired,
	}

	encoded, err := json.Marshal(output)
	if err != nil {
		return "", fmt.Errorf("encode sysupdate result: %w", err)
	}
	return string(encoded), nil
}
