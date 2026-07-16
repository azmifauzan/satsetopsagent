package executor

import (
	"fmt"
	"strconv"
	"time"

	"github.com/satsetops/agent/internal/exec"
)

// hostLogFiles is a fixed allow-list of host-visible log files collectLogs
// can tail via the "source" payload key, as an alternative to a docker
// container's own stdout log. Deliberately closed (no arbitrary path) - this
// exists so operators can see what a container's own captured
// error_log/access_log actually says when a custom nginx config redirects
// it to a file instead of stdout, which "docker logs" never sees.
var hostLogFiles = map[string]string{
	"nginx-error":  "/var/log/satsetops/nginx/error.log",
	"nginx-access": "/var/log/satsetops/nginx/access.log",
}

// letsencryptLogPath is certbot's own log, written inside nginx-certbot's
// container filesystem - it is not bind-mounted to the host, so it can only
// be read via "docker exec" while the container is alive, not as a plain
// host path like hostLogFiles above.
const letsencryptLogPath = "/var/log/letsencrypt/letsencrypt.log"

func collectLogs(payload map[string]any, runner exec.Runner) (string, error) {
	tailStr := tailFromPayload(payload)

	if source, ok := payload["source"].(string); ok && source != "" {
		if source == "letsencrypt" {
			return collectLetsencryptLog(payload, tailStr, runner)
		}
		path, known := hostLogFiles[source]
		if !known {
			return "", fmt.Errorf("unknown log source %q", source)
		}
		out, err := runner.Run("tail", "-n", tailStr, "--", path)
		if err != nil {
			return "", fmt.Errorf("failed to read %s: %w", path, err)
		}
		return out, nil
	}

	name, ok := payload["name"].(string)
	if !ok || name == "" {
		return "", fmt.Errorf("missing or invalid 'name' in payload")
	}
	if !nameRegex.MatchString(name) {
		return "", fmt.Errorf("invalid container name format")
	}

	out, err := runner.Run("docker", "logs", "--tail", tailStr, name)
	if err != nil {
		return "", fmt.Errorf("failed to collect logs for %s: %w", name, err)
	}

	return out, nil
}

// collectLetsencryptLog starts the target container (if not already
// running) and races to read certbot's own log via "docker exec" before the
// container can crash again, retrying briefly since the read window after a
// crash-looping container's start can be under a second.
func collectLetsencryptLog(payload map[string]any, tailStr string, runner exec.Runner) (string, error) {
	name, ok := payload["name"].(string)
	if !ok || name == "" {
		name = "nginx-certbot"
	}
	if !nameRegex.MatchString(name) {
		return "", fmt.Errorf("invalid container name format")
	}

	_, _ = runner.Run("docker", "start", name)

	var lastErr error
	for i := 0; i < 30; i++ {
		out, err := runner.Run("docker", "exec", name, "tail", "-n", tailStr, letsencryptLogPath)
		if err == nil {
			return out, nil
		}
		lastErr = err
		time.Sleep(200 * time.Millisecond)
	}

	return "", fmt.Errorf("could not read %s from %s before it stopped: %w", letsencryptLogPath, name, lastErr)
}

func tailFromPayload(payload map[string]any) string {
	var tailStr string
	switch t := payload["tail"].(type) {
	case string:
		tailStr = t
	case float64:
		tailStr = strconv.Itoa(int(t))
	case int:
		tailStr = strconv.Itoa(t)
	default:
		return "100" // Default tail
	}

	tailVal, err := strconv.Atoi(tailStr)
	if err != nil || tailVal < 0 {
		return "100"
	}

	return tailStr
}
