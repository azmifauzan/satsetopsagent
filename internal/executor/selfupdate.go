package executor

import (
	"fmt"
	"runtime"

	"github.com/satsetops/agent/internal/exec"
)

// agentBinaryPath and downloadBaseURL are package vars (not consts) so tests
// can point them at a temp path / fake host instead of the real system path
// and GitHub.
var (
	agentBinaryPath = "/usr/local/bin/satsetopsagent"
	downloadBaseURL = "https://github.com/azmifauzan/satsetopsagent/releases/download"
)

// selfUpdate downloads the requested release's binary for this host's
// architecture, replaces the running binary, and schedules a detached
// restart of the systemd unit a couple seconds out — long enough for this
// call to return and the poller to report success back to the web app
// before the process is actually killed. Restarting synchronously here
// (`systemctl restart` while we ARE that unit) would SIGTERM us before we
// ever got to report the result.
func selfUpdate(payload map[string]any, runner exec.Runner) (string, error) {
	targetVersion, _ := payload["version"].(string)
	if targetVersion == "" {
		return "", fmt.Errorf("self_update: missing version in payload")
	}

	url := fmt.Sprintf("%s/%s/satsetopsagent-linux-%s", downloadBaseURL, targetVersion, runtime.GOARCH)
	tempPath := agentBinaryPath + ".new"

	if _, err := runner.Run("curl", "-fsSL", "-o", tempPath, "--", url); err != nil {
		return "", fmt.Errorf("download %s: %w", url, err)
	}
	if _, err := runner.Run("chmod", "+x", tempPath); err != nil {
		return "", fmt.Errorf("chmod new binary: %w", err)
	}
	// Same-directory mv is an atomic rename on the same filesystem — no
	// window where the path exists but is a partially-written file.
	if _, err := runner.Run("mv", tempPath, agentBinaryPath); err != nil {
		return "", fmt.Errorf("install new binary: %w", err)
	}

	if _, err := runner.Run("sh", "-c",
		"nohup sh -c 'sleep 2 && systemctl restart satsetops-agent' >/dev/null 2>&1 &"); err != nil {
		return "", fmt.Errorf("schedule restart: %w", err)
	}

	return fmt.Sprintf(`{"updated_to":%q}`, targetVersion), nil
}
