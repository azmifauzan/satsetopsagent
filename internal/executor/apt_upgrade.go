package executor

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/satsetops/agent/internal/distro"
	"github.com/satsetops/agent/internal/exec"
)

// aptUpgrade runs once, right at the start of the initial hardening batch on
// a freshly confirmed-clean VPS — a provider's base image is sometimes
// already stale by the time a user actually boots it, so this gets the box
// to a known-current baseline before anything else touches it. It's a full
// upgrade (all packages, not just security origin), deliberately different
// from sysupdateHarden's ongoing security-only policy: a one-time refresh
// on a box nothing is running on yet is a different risk profile than a
// recurring auto-upgrade on a live server.
func aptUpgrade(payload map[string]any, runner exec.Runner) (string, error) {
	family, err := distro.Detect(runner)
	if err != nil {
		return "", fmt.Errorf("detect distro: %w", err)
	}

	switch family {
	case distro.RHEL:
		manager := "dnf"
		if !distro.CommandExists(runner, "dnf") {
			manager = "yum"
		}
		if _, err := withRetry(3, 10*time.Second, func() (string, error) {
			return runner.Run("bash", "-c", manager+" upgrade -y")
		}); err != nil {
			return "", fmt.Errorf("failed to %s upgrade: %w", manager, err)
		}
	case distro.Arch:
		if _, err := withRetry(3, 10*time.Second, func() (string, error) {
			return runner.Run("bash", "-c", "pacman -Syu --noconfirm")
		}); err != nil {
			return "", fmt.Errorf("failed to pacman -Syu: %w", err)
		}
	default: // Debian and Unknown both fall back to apt — apt is the
		// majority case and the safest generic default when detection
		// itself is inconclusive.
		if _, err := withRetry(3, 10*time.Second, func() (string, error) {
			return runner.Run("bash", "-c", "DEBIAN_FRONTEND=noninteractive apt-get update")
		}); err != nil {
			return "", fmt.Errorf("failed to apt-get update: %w", err)
		}
		if _, err := withRetry(3, 10*time.Second, func() (string, error) {
			return runner.Run("bash", "-c", "DEBIAN_FRONTEND=noninteractive apt-get upgrade -y")
		}); err != nil {
			return "", fmt.Errorf("failed to apt-get upgrade: %w", err)
		}
	}

	_, rebootErr := runner.Run("test", "-f", "/var/run/reboot-required")

	output := struct {
		Upgraded       bool `json:"upgraded"`
		RebootRequired bool `json:"reboot_required"`
	}{
		Upgraded:       true,
		RebootRequired: rebootErr == nil,
	}

	encoded, err := json.Marshal(output)
	if err != nil {
		return "", fmt.Errorf("encode apt_upgrade result: %w", err)
	}
	return string(encoded), nil
}
