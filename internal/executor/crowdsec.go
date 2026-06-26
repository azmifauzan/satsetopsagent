package executor

import (
	"fmt"
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

	return "crowdsec installed with bouncer and limits", nil
}
