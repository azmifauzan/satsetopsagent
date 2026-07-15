package executor

import (
	"fmt"

	"github.com/satsetops/agent/internal/exec"
)

// Dispatch only executes action types compiled into the agent. There is no
// fallback to a shell or arbitrary command execution.
func Dispatch(commandType string, payload map[string]any, runner exec.Runner) (string, error) {
	switch commandType {
	case "scan_vps":
		return scanVPS(runner)
	case "apt_upgrade":
		return aptUpgrade(payload, runner)
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
	case "security_audit":
		return securityAudit(runner)
	case "reboot_server":
		return rebootServer(runner)
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
	case "self_update":
		return selfUpdate(payload, runner)
	case "delete_app":
		return deleteApp(payload, runner)
	default:
		return "", fmt.Errorf("unsupported command type: %s", commandType)
	}
}
