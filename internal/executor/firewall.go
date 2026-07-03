package executor

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/satsetops/agent/internal/distro"
	"github.com/satsetops/agent/internal/exec"
)

func hardenFirewall(payload map[string]any, runner exec.Runner) (string, error) {
	family, err := distro.Detect(runner)
	if err != nil {
		return "", fmt.Errorf("detect distro: %w", err)
	}

	switch family {
	case distro.RHEL:
		return hardenFirewallRHEL(runner)
	case distro.Arch:
		return hardenFirewallArch(runner)
	default:
		return hardenFirewallDebian(runner)
	}
}

func hardenFirewallDebian(runner exec.Runner) (string, error) {
	commands := [][]string{
		{"default", "deny", "incoming"},
		{"default", "allow", "outgoing"},
		{"allow", "22/tcp"},
		{"allow", "80/tcp"},
		{"allow", "443/tcp"},
		{"--force", "enable"},
	}

	var output strings.Builder
	for _, args := range commands {
		out, err := runner.Run("ufw", args...)
		if err != nil {
			return "", fmt.Errorf("ufw %s: %w", strings.Join(args, " "), err)
		}
		output.WriteString(out + "\n")
	}

	return "firewall hardened", nil
}

func hardenFirewallRHEL(runner exec.Runner) (string, error) {
	if _, err := runner.Run("systemctl", "enable", "--now", "firewalld"); err != nil {
		return "", fmt.Errorf("failed to enable firewalld: %w", err)
	}

	for _, service := range []string{"ssh", "http", "https"} {
		if _, err := runner.Run("firewall-cmd", "--permanent", "--add-service="+service); err != nil {
			return "", fmt.Errorf("firewall-cmd --add-service=%s: %w", service, err)
		}
	}

	if _, err := runner.Run("firewall-cmd", "--reload"); err != nil {
		return "", fmt.Errorf("firewall-cmd --reload: %w", err)
	}

	return "firewall hardened", nil
}

func hardenFirewallArch(runner exec.Runner) (string, error) {
	if !distro.CommandExists(runner, "iptables") {
		if _, err := runner.Run("bash", "-c", "pacman -S --noconfirm iptables"); err != nil {
			return "", fmt.Errorf("failed to install iptables: %w", err)
		}
	}

	commands := [][]string{
		{"-P", "INPUT", "DROP"},
		{"-P", "OUTPUT", "ACCEPT"},
		{"-A", "INPUT", "-i", "lo", "-j", "ACCEPT"},
		{"-A", "INPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"},
		{"-A", "INPUT", "-p", "tcp", "--dport", "22", "-j", "ACCEPT"},
		{"-A", "INPUT", "-p", "tcp", "--dport", "80", "-j", "ACCEPT"},
		{"-A", "INPUT", "-p", "tcp", "--dport", "443", "-j", "ACCEPT"},
	}
	for _, args := range commands {
		if _, err := runner.Run("iptables", args...); err != nil {
			return "", fmt.Errorf("iptables %s: %w", strings.Join(args, " "), err)
		}
	}

	return "firewall hardened", nil
}

func setFirewallRule(payload map[string]any, runner exec.Runner) (string, error) {
	portVal, ok := payload["port"]
	if !ok {
		return "", fmt.Errorf("missing port in payload")
	}

	// Ensure port is numeric to prevent injection
	portStr := fmt.Sprintf("%v", portVal)
	portStr = strings.TrimSpace(portStr)
	// it might have /tcp or /udp. For safety, extract digits
	parts := strings.Split(portStr, "/")
	if len(parts) > 2 {
		return "", fmt.Errorf("invalid port format")
	}

	portNum, err := strconv.Atoi(parts[0])
	if err != nil || portNum <= 0 || portNum > 65535 {
		return "", fmt.Errorf("invalid port number: %s", parts[0])
	}

	actionVal, ok := payload["action"]
	if !ok {
		actionVal = "allow"
	}
	action := fmt.Sprintf("%v", actionVal)
	if action != "allow" && action != "deny" {
		return "", fmt.Errorf("invalid action: %s", action)
	}

	family, err := distro.Detect(runner)
	if err != nil {
		return "", fmt.Errorf("detect distro: %w", err)
	}

	switch family {
	case distro.RHEL:
		// firewall-cmd's --add-port/--remove-port require an explicit
		// protocol (e.g. "8080/tcp") — unlike ufw, "8080" alone is a syntax
		// error. The only real caller (ToolRegistry's AI tool-calling path)
		// always sends a bare integer port with no protocol, so default to
		// tcp whenever the payload didn't specify one.
		portWithProto := portStr
		if len(parts) == 1 {
			portWithProto = parts[0] + "/tcp"
		}
		return setFirewallRuleRHEL(runner, portWithProto, action)
	case distro.Arch:
		return setFirewallRuleArch(runner, parts[0], action)
	default:
		return setFirewallRuleDebian(runner, portStr, action)
	}
}

func setFirewallRuleDebian(runner exec.Runner, portStr, action string) (string, error) {
	out, err := runner.Run("ufw", action, portStr)
	if err != nil {
		return "", fmt.Errorf("ufw %s %s: %w", action, portStr, err)
	}
	return out, nil
}

func setFirewallRuleRHEL(runner exec.Runner, portStr, action string) (string, error) {
	flag := "--add-port=" + portStr
	if action == "deny" {
		flag = "--remove-port=" + portStr
	}
	if _, err := runner.Run("firewall-cmd", "--permanent", flag); err != nil {
		return "", fmt.Errorf("firewall-cmd %s: %w", flag, err)
	}
	out, err := runner.Run("firewall-cmd", "--reload")
	if err != nil {
		return "", fmt.Errorf("firewall-cmd --reload: %w", err)
	}
	return out, nil
}

func setFirewallRuleArch(runner exec.Runner, port, action string) (string, error) {
	flag := "-A"
	if action == "deny" {
		flag = "-D"
	}
	out, err := runner.Run("iptables", flag, "INPUT", "-p", "tcp", "--dport", port, "-j", "ACCEPT")
	if err != nil {
		return "", fmt.Errorf("iptables %s INPUT --dport %s: %w", flag, port, err)
	}
	return out, nil
}
