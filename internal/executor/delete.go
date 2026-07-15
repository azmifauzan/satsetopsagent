package executor

import (
	"fmt"
	"strings"

	"github.com/satsetops/agent/internal/exec"
)

// deleteApp tears down an application permanently: removes its container
// and, if a domain was attached, its nginx vhost config + SSL reload. Called
// once, right before the web side hard-deletes the Application row — unlike
// stop_container/restart_container this has no way back.
func deleteApp(payload map[string]any, runner exec.Runner) (string, error) {
	name, ok := payload["name"].(string)
	if !ok || name == "" {
		return "", fmt.Errorf("missing or invalid 'name' in payload")
	}
	if !nameRegex.MatchString(name) {
		return "", fmt.Errorf("invalid container name format")
	}

	if _, err := runner.Run("docker", "rm", "-f", name); err != nil {
		if !strings.Contains(err.Error(), "No such container") {
			return "", fmt.Errorf("failed to remove container %s: %w", name, err)
		}
	}

	domain, _ := payload["domain"].(string)
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return fmt.Sprintf("container %s removed", name), nil
	}
	if !domainRegex.MatchString(domain) {
		return "", fmt.Errorf("invalid domain format (must be FQDN)")
	}

	configFile := fmt.Sprintf("/etc/nginx/user_conf.d/%s.conf", domain)
	if _, err := runner.Run("rm", "-f", configFile); err != nil {
		return "", fmt.Errorf("failed to remove vhost config for %s: %w", domain, err)
	}
	if _, err := runner.Run("docker", "kill", "--signal=HUP", "nginx-certbot"); err != nil {
		return "", fmt.Errorf("failed to reload nginx-certbot: %w", err)
	}

	return fmt.Sprintf("container %s removed, vhost for %s deleted", name, domain), nil
}
