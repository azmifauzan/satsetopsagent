package executor

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/satsetops/agent/internal/exec"
)

// Dispatch only executes action types compiled into the agent. There is no
// fallback to a shell or arbitrary command execution.
func Dispatch(commandType string, payload map[string]any, runner exec.Runner) (string, error) {
	switch commandType {
	case "scan_vps":
		return scanVPS(runner)
	case "harden_firewall":
		return hardenFirewall(payload, runner)
	case "ssh_harden":
		return sshHarden(payload, runner)
	case "install_crowdsec":
		return installCrowdsec(payload, runner)
	case "sysupdate":
		return sysupdateHarden(payload, runner)
	case "docker_harden":
		return dockerHarden(payload, runner)
	case "setup_nginx_proxy":
		return setupNginxProxy(payload, runner)
	case "set_firewall_rule":
		return setFirewallRule(payload, runner)
	case "deploy_app":
		return deployApp(payload, runner)
	case "restart_container":
		return restartContainer(payload, runner)
	case "stop_container":
		return stopContainer(payload, runner)
	case "attach_domain_ssl":
		return attachDomainSSL(payload, runner)
	case "collect_logs":
		return collectLogs(payload, runner)
	case "backup_now":
		return backupNow(payload, runner)
	case "restore":
		return restoreBackup(payload, runner)
	default:
		return "", fmt.Errorf("unsupported command type: %s", commandType)
	}
}

func scanVPS(runner exec.Runner) (string, error) {
	_, dockerSocketError := os.Stat("/var/run/docker.sock")
	
	clean := true
	var findings []string

	// Check if port 80 or 443 are in use by something other than our own nginx-certbot proxy.
	nginxRunning, _ := runner.Run("docker", "inspect", "-f", "{{.State.Running}}", "nginx-certbot")
	nginxAlreadySetup := strings.TrimSpace(nginxRunning) == "true"
	if !nginxAlreadySetup {
		if out, err := runner.Run("ss", "-tuln"); err == nil {
			if strings.Contains(out, ":80 ") {
				clean = false
				findings = append(findings, "Port 80 is already in use")
			}
			if strings.Contains(out, ":443 ") {
				clean = false
				findings = append(findings, "Port 443 is already in use")
			}
		}
	}

	// Check for common panels or services
	out, err := runner.Run("systemctl", "list-units", "--type=service", "--state=running")
	if err == nil {
		suspicious := []string{"apache2", "nginx", "mysql", "cpanel"}
		for _, s := range suspicious {
			if strings.Contains(out, s+".service") {
				clean = false
				findings = append(findings, fmt.Sprintf("Service %s is running", s))
			}
		}
	}

	if findings == nil {
		findings = []string{}
	}

	report := struct {
		Docker       bool     `json:"docker"`
		Clean        bool     `json:"clean"`
		Findings     []string `json:"findings"`
		OS           string   `json:"os"`
		Architecture string   `json:"architecture"`
	}{
		Docker:       dockerSocketError == nil,
		Clean:        clean,
		Findings:     findings,
		OS:           runtime.GOOS,
		Architecture: runtime.GOARCH,
	}

	encoded, err := json.Marshal(report)
	if err != nil {
		return "", fmt.Errorf("encode VPS scan: %w", err)
	}
	return string(encoded), nil
}
