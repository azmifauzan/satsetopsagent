package reporter

import (
	"regexp"
	"strings"
	"time"

	"github.com/satsetops/agent/internal/api"
	"github.com/satsetops/agent/internal/exec"
)

var (
	// Example log: "Challenge failed for domain example.com"
	// We want to capture the domain from: "Challenge failed for domain example.com"
	challengeFailedRegex = regexp.MustCompile(`(?i)Challenge failed for domain ([a-zA-Z0-9.-]+)`)
)

func CollectSSLErrors(runner exec.Runner) ([]api.SSLError, error) {
	// Let's Encrypt logs are output by the jonasal/nginx-certbot container.
	// We will grab the last 15 minutes of logs.
	output, err := runner.Run("docker", "logs", "--since", "15m", "nginx-certbot")
	if err != nil || len(strings.TrimSpace(output)) == 0 {
		return nil, nil // If container not running or no logs, just return nil
	}

	lines := strings.Split(output, "\n")
	var errors []api.SSLError
	seenDomains := make(map[string]bool)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		matches := challengeFailedRegex.FindStringSubmatch(line)
		if len(matches) > 1 {
			domain := matches[1]
			if !seenDomains[domain] {
				seenDomains[domain] = true
				errors = append(errors, api.SSLError{
					Domain: domain,
					Error:  "HTTP-01 challenge failed. Pastikan A Record DNS mengarah ke IP VPS ini.",
					Time:   time.Now().Format(time.RFC3339),
				})
			}
		}
	}

	return errors, nil
}
