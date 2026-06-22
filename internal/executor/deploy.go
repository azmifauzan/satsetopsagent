package executor

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/satsetops/agent/internal/exec"
)

var (
	nameRegex  = regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`)
	imageRegex = regexp.MustCompile(`^[a-zA-Z0-9_./:@-]+$`)
)

func deployApp(payload map[string]any, runner exec.Runner) (string, error) {
	image, ok := payload["image"].(string)
	if !ok || image == "" {
		return "", fmt.Errorf("missing or invalid 'image' in payload")
	}
	if !imageRegex.MatchString(image) {
		return "", fmt.Errorf("invalid image name format")
	}

	name, ok := payload["name"].(string)
	if !ok || name == "" {
		return "", fmt.Errorf("missing or invalid 'name' in payload")
	}
	if !nameRegex.MatchString(name) {
		return "", fmt.Errorf("invalid container name format")
	}

	var portStr string
	switch p := payload["port"].(type) {
	case string:
		portStr = p
	case float64:
		portStr = strconv.Itoa(int(p))
	case int:
		portStr = strconv.Itoa(p)
	default:
		return "", fmt.Errorf("missing or invalid 'port' in payload")
	}

	portVal, err := strconv.Atoi(portStr)
	if err != nil || portVal < 1 || portVal > 65535 {
		return "", fmt.Errorf("invalid port value: %s", portStr)
	}

	// Pull the image first
	_, err = runner.Run("docker", "pull", image)
	if err != nil {
		return "", fmt.Errorf("failed to pull image %s: %w", image, err)
	}

	// Remove container if it already exists
	_, _ = runner.Run("docker", "rm", "-f", name)

	// Build run args
	args := []string{"run", "-d", "--name", name, "-p", fmt.Sprintf("127.0.0.1:%s:%s", portStr, portStr), "--restart", "unless-stopped"}

	// Extract env variables
	if envs, ok := payload["env"].(map[string]any); ok {
		for k, v := range envs {
			valStr := fmt.Sprintf("%v", v)
			args = append(args, "-e", fmt.Sprintf("%s=%s", k, valStr))
		}
	} else if envsMap, ok := payload["env"].(map[string]string); ok {
		for k, v := range envsMap {
			args = append(args, "-e", fmt.Sprintf("%s=%s", k, v))
		}
	}

	args = append(args, image)

	// Run container
	containerID, err := runner.Run("docker", args...)
	if err != nil {
		return "", fmt.Errorf("failed to run container %s: %w", name, err)
	}

	return strings.TrimSpace(containerID), nil
}

func restartContainer(payload map[string]any, runner exec.Runner) (string, error) {
	name, ok := payload["name"].(string)
	if !ok || name == "" {
		return "", fmt.Errorf("missing or invalid 'name' in payload")
	}
	if !nameRegex.MatchString(name) {
		return "", fmt.Errorf("invalid container name format")
	}

	_, err := runner.Run("docker", "restart", name)
	if err != nil {
		return "", fmt.Errorf("failed to restart container %s: %w", name, err)
	}
	return fmt.Sprintf("container %s restarted successfully", name), nil
}

func stopContainer(payload map[string]any, runner exec.Runner) (string, error) {
	name, ok := payload["name"].(string)
	if !ok || name == "" {
		return "", fmt.Errorf("missing or invalid 'name' in payload")
	}
	if !nameRegex.MatchString(name) {
		return "", fmt.Errorf("invalid container name format")
	}

	_, err := runner.Run("docker", "stop", name)
	if err != nil {
		return "", fmt.Errorf("failed to stop container %s: %w", name, err)
	}
	return fmt.Sprintf("container %s stopped successfully", name), nil
}
