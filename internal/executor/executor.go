package executor

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
)

// Dispatch only executes action types compiled into the agent. There is no
// fallback to a shell or arbitrary command execution.
func Dispatch(commandType string, payload map[string]any) (string, error) {
	switch commandType {
	case "scan_vps":
		return scanVPS()
	case "harden_firewall":
		return hardenFirewall(payload)
	case "ssh_harden":
		return sshHarden(payload)
	case "install_crowdsec":
		return installCrowdsec(payload)
	case "set_firewall_rule":
		return setFirewallRule(payload)
	case "deploy_app":
		return deployApp(payload)
	case "restart_container":
		return restartContainer(payload)
	case "stop_container":
		return stopContainer(payload)
	case "attach_domain_ssl":
		return attachDomainSsl(payload)
	case "collect_logs":
		return collectLogs(payload)
	case "backup_now":
		return backupNow(payload)
	default:
		return "", fmt.Errorf("unsupported command type: %s", commandType)
	}
}

func scanVPS() (string, error) {
	_, dockerSocketError := os.Stat("/var/run/docker.sock")
	report := struct {
		Docker       bool   `json:"docker"`
		Clean        bool   `json:"clean"`
		OS           string `json:"os"`
		Architecture string `json:"architecture"`
	}{
		Docker:       dockerSocketError == nil,
		Clean:        true,
		OS:           runtime.GOOS,
		Architecture: runtime.GOARCH,
	}

	encoded, err := json.Marshal(report)
	if err != nil {
		return "", fmt.Errorf("encode VPS scan: %w", err)
	}
	return string(encoded), nil
}
