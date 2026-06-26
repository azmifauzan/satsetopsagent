package executor

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/satsetops/agent/internal/exec"
)

var (
	nameRegex         = regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`)
	imageRegex        = regexp.MustCompile(`^[a-zA-Z0-9_./:@-]+$`)
	registryHostRegex = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.:-]*$`)
	registryUserRegex = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._@-]*$`)
)

// registryHostOf extracts the registry host from an image reference, the
// same way the Docker CLI itself decides whether a ref's first path
// segment is a registry host (contains "." or ":", or is "localhost")
// versus a Docker Hub repository (e.g. "nginx" or "library/nginx").
func registryHostOf(image string) string {
	parts := strings.SplitN(image, "/", 2)
	if len(parts) < 2 {
		// No "/" at all means it's a bare Docker Hub repo (e.g.
		// "nginx:latest") — that colon is the tag separator, not a
		// registry port, since a registry host is never valid on its own
		// without a path after it.
		return ""
	}
	first := parts[0]
	if first == "localhost" || strings.ContainsAny(first, ".:") {
		return first
	}
	return ""
}

// loginRegistry runs `docker login` against the image's registry host if
// the payload carries credentials for it. Password goes via stdin, never
// as a CLI arg, so it doesn't show up in `ps`.
func loginRegistry(image string, payload map[string]any, runner exec.Runner) error {
	username, _ := payload["registry_username"].(string)
	password, _ := payload["registry_password"].(string)
	if username == "" || password == "" {
		return nil
	}

	host := registryHostOf(image)
	if host == "" {
		return fmt.Errorf("registry credentials provided but image %q has no registry host", image)
	}
	// Both become positional/flag-value args to `docker login` below — a
	// value starting with "-" could be parsed as a flag by docker's argv
	// parser (e.g. a host of "--config=/tmp/evil" or similar).
	if !registryHostRegex.MatchString(host) {
		return fmt.Errorf("invalid registry host format: %q", host)
	}
	if !registryUserRegex.MatchString(username) {
		return fmt.Errorf("invalid registry username format")
	}

	if _, err := runner.RunWithStdin("docker", password, "login", "-u", username, "--password-stdin", "--", host); err != nil {
		return fmt.Errorf("failed to login to registry %s: %w", host, err)
	}

	return nil
}

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

	if err := loginRegistry(image, payload, runner); err != nil {
		return "", err
	}

	// Pull the image first
	_, err = runner.Run("docker", "pull", image)
	if err != nil {
		return "", fmt.Errorf("failed to pull image %s: %w", image, err)
	}

	// Remove container if it already exists
	_, _ = runner.Run("docker", "rm", "-f", name)

	// App containers run on the satsetops-proxy Docker network so nginx-certbot
	// can reach them by container name (proxy_pass http://name:port). No host
	// port binding needed — all traffic enters via nginx-certbot on 80/443.
	args := []string{"run", "-d", "--name", name, "--network", "satsetops-proxy", "--restart", "unless-stopped"}

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
