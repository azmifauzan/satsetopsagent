package executor

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/satsetops/agent/internal/exec"
)

func hardenFirewall(payload map[string]any, runner exec.Runner) (string, error) {
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

	out, err := runner.Run("ufw", action, portStr)
	if err != nil {
		return "", fmt.Errorf("ufw %s %s: %w", action, portStr, err)
	}
	
	return out, nil
}
