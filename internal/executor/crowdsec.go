package executor

import (
	"fmt"
	"net"
	"strings"

	"github.com/satsetops/agent/internal/exec"
)

func installCrowdsec(payload map[string]any, runner exec.Runner) (string, error) {
	// Add repo
	_, err := runner.Run("bash", "-c", "curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | bash")
	if err != nil {
		return "", fmt.Errorf("failed to add crowdsec repo: %w", err)
	}

	// Install engine. DEBIAN_FRONTEND=noninteractive is required: apt-get
	// otherwise tries a debconf dialog and fails outright under systemd,
	// which gives the process no controlling TTY.
	_, err = runner.Run("bash", "-c", "DEBIAN_FRONTEND=noninteractive apt-get install -y crowdsec")
	if err != nil {
		return "", fmt.Errorf("failed to install crowdsec engine: %w", err)
	}

	// Install limited collections
	collections := []string{"crowdsecurity/sshd", "crowdsecurity/nginx", "crowdsecurity/http-cve"}
	for _, coll := range collections {
		_, err = runner.Run("cscli", "collections", "install", coll)
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
	_, err = runner.Run("bash", "-c", "DEBIAN_FRONTEND=noninteractive apt-get install -y crowdsec-firewall-bouncer-iptables")
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

	if err := whitelistPlatformIPs(payload, runner); err != nil {
		return "", err
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
