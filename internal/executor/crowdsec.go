package executor

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/satsetops/agent/internal/distro"
	"github.com/satsetops/agent/internal/exec"
)

func installCrowdsec(payload map[string]any, runner exec.Runner) (string, error) {
	family, err := distro.Detect(runner)
	if err != nil {
		return "", fmt.Errorf("detect distro: %w", err)
	}

	// Arch has no first-party CrowdSec package or repo (AUR-only, which
	// this agent deliberately never uses — AUR packages are unreviewed
	// community submissions, not something to auto-install as root).
	// Reporting a clean skip here — rather than a failure — keeps the rest
	// of the hardening batch going instead of aborting on it.
	if family == distro.Arch {
		return "crowdsec installation skipped: no supported package source on Arch", nil
	}

	repoScript := "script.deb.sh"
	installCmd := "DEBIAN_FRONTEND=noninteractive apt-get install -y crowdsec"
	bouncerCmd := "DEBIAN_FRONTEND=noninteractive apt-get install -y crowdsec-firewall-bouncer-iptables"
	if family == distro.RHEL {
		repoScript = "script.rpm.sh"
		manager := "dnf"
		if !distro.CommandExists(runner, "dnf") {
			manager = "yum"
		}
		installCmd = manager + " install -y crowdsec"
		bouncerCmd = manager + " install -y crowdsec-firewall-bouncer-iptables"
	}

	// Add repo
	_, err = withRetry(3, 5*time.Second, func() (string, error) {
		return runner.Run("bash", "-c", "curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/"+repoScript+" | bash")
	})
	if err != nil {
		return "", fmt.Errorf("failed to add crowdsec repo: %w", err)
	}

	// packagecloud's install script doesn't reliably refresh the local
	// package index on its own — CrowdSec's own install docs list this as
	// its own explicit step, and skipping it produced a real production
	// failure: the engine install (using an already-warm cache) succeeded,
	// but the bouncer install right after failed with "Unable to locate
	// package crowdsec-firewall-bouncer-iptables" — the exact symptom of a
	// stale apt index that never picked up the newly-added repo's listing.
	if family != distro.RHEL {
		_, err = withRetry(3, 10*time.Second, func() (string, error) {
			return runner.Run("bash", "-c", "DEBIAN_FRONTEND=noninteractive apt-get update")
		})
		if err != nil {
			return "", fmt.Errorf("failed to refresh apt index after adding crowdsec repo: %w", err)
		}
	}

	// Install engine.
	_, err = withRetry(3, 10*time.Second, func() (string, error) {
		return runner.Run("bash", "-c", installCmd)
	})
	if err != nil {
		return "", fmt.Errorf("failed to install crowdsec engine: %w", err)
	}

	// Refresh cscli's local hub index before installing anything from it —
	// a fresh engine install's cached index can already be stale/mismatched
	// against what the hub actually serves, which fails every subsequent
	// `cscli collections install` with "Downloaded version doesn't match
	// index, please 'hub update'" (hit in production on two separate VPS,
	// after the --force fix below was already in place — a distinct bug).
	_, err = withRetry(3, 5*time.Second, func() (string, error) {
		return runner.Run("cscli", "hub", "update")
	})
	if err != nil {
		return "", fmt.Errorf("failed to update crowdsec hub index: %w", err)
	}

	// Install limited collections. --force is required, not optional — a
	// production VPS hit "crowdsecurity/sshd is tainted, won't enable
	// unless --force" when the collection's underlying scenarios were
	// already present locally (base image or an earlier interrupted
	// attempt) and modified from upstream. --force is safe/idempotent
	// whether the item is absent, already correctly installed, or tainted.
	collections := []string{"crowdsecurity/sshd", "crowdsecurity/nginx", "crowdsecurity/http-cve"}
	for _, coll := range collections {
		_, err = withRetry(3, 5*time.Second, func() (string, error) {
			return runner.Run("cscli", "collections", "install", coll, "--force")
		})
		if err != nil && !strings.Contains(err.Error(), "already installed") {
			return "", fmt.Errorf("failed to install collection %s: %w", coll, err)
		}
	}

	// Systemd drop-in for resource limit
	dropinDir := "/etc/systemd/system/crowdsec.service.d"
	_, err = runner.Run("mkdir", "-p", dropinDir)
	if err != nil {
		return "", fmt.Errorf("failed to create systemd drop-in dir: %w", err)
	}

	cgroupConfig := `[Service]
MemoryHigh=150M
MemoryMax=250M
CPUQuota=20%
`
	_, err = runner.Run("bash", "-c", fmt.Sprintf("echo -e '%s' > %s/limits.conf", cgroupConfig, dropinDir))
	if err != nil {
		return "", fmt.Errorf("failed to write cgroup limits: %w", err)
	}

	// Install bouncer
	_, err = withRetry(3, 10*time.Second, func() (string, error) {
		return runner.Run("bash", "-c", bouncerCmd)
	})
	if err != nil {
		return "", fmt.Errorf("failed to install crowdsec bouncer: %w", err)
	}

	// Reload & restart
	_, err = runner.Run("systemctl", "daemon-reload")
	if err != nil {
		return "", fmt.Errorf("failed to daemon-reload: %w", err)
	}
	_, err = runner.Run("systemctl", "restart", "crowdsec")
	if err != nil {
		return "", fmt.Errorf("failed to restart crowdsec: %w", err)
	}

	if payload != nil {
		if err := whitelistPlatformIPs(payload, runner); err != nil {
			return "", err
		}
	}

	return "crowdsec installed with bouncer and limits", nil
}

// whitelistPlatformIPs allowlists SatsetOps' own outbound IP(s) (SSH
// auto-provisioning, SSH Console) in CrowdSec so a burst of legitimate
// connections is never mistaken for a bruteforce attempt — an auto-ban here
// would permanently lock the platform out of the box, with no other way
// back in.
func whitelistPlatformIPs(payload map[string]any, runner exec.Runner) error {
	raw, ok := payload["whitelist_ips"].([]any)
	if !ok || len(raw) == 0 {
		return nil
	}

	const listName = "satsetops-platform"

	_, err := runner.Run("cscli", "allowlists", "create", listName, "-d", "SatsetOps platform IPs")
	if err != nil && !strings.Contains(err.Error(), "already exist") {
		return fmt.Errorf("failed to create crowdsec allowlist: %w", err)
	}

	for _, ip := range raw {
		ipStr, ok := ip.(string)
		if !ok || net.ParseIP(ipStr) == nil {
			continue
		}

		_, err := runner.Run("cscli", "allowlists", "add", listName, ipStr)
		if err != nil && !strings.Contains(err.Error(), "already") {
			return fmt.Errorf("failed to whitelist %s: %w", ipStr, err)
		}
	}

	return nil
}
