package executor

import (
	"fmt"
	"strconv"

	"github.com/satsetops/agent/internal/exec"
)

func collectLogs(payload map[string]any, runner exec.Runner) (string, error) {
	name, ok := payload["name"].(string)
	if !ok || name == "" {
		return "", fmt.Errorf("missing or invalid 'name' in payload")
	}
	if !nameRegex.MatchString(name) {
		return "", fmt.Errorf("invalid container name format")
	}

	var tailStr string
	switch t := payload["tail"].(type) {
	case string:
		tailStr = t
	case float64:
		tailStr = strconv.Itoa(int(t))
	case int:
		tailStr = strconv.Itoa(t)
	default:
		tailStr = "100" // Default tail
	}

	tailVal, err := strconv.Atoi(tailStr)
	if err != nil || tailVal < 0 {
		tailStr = "100"
	}

	out, err := runner.Run("docker", "logs", "--tail", tailStr, name)
	if err != nil {
		return "", fmt.Errorf("failed to collect logs for %s: %w", name, err)
	}

	return out, nil
}
