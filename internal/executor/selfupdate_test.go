package executor

import (
	"errors"
	"runtime"
	"strings"
	"testing"

	"github.com/satsetops/agent/internal/exec"
)

func TestSelfUpdateDownloadsSwapsAndSchedulesRestart(t *testing.T) {
	runner := exec.NewFakeRunner()

	output, err := Dispatch("self_update", map[string]any{"version": "v0.3.1"}, runner)
	if err != nil {
		t.Fatalf("self_update: %v", err)
	}
	if !strings.Contains(output, "v0.3.1") {
		t.Fatalf("expected output to mention the new version, got %q", output)
	}

	wantURL := downloadBaseURL + "/v0.3.1/satsetopsagent-linux-" + runtime.GOARCH
	tempPath := agentBinaryPath + ".new"

	if !runner.HasCommand("curl -fsSL -o " + tempPath + " -- " + wantURL) {
		t.Fatalf("expected a download command, got: %v", runner.Commands)
	}
	if !runner.HasCommand("chmod +x " + tempPath) {
		t.Fatalf("expected new binary to be made executable, got: %v", runner.Commands)
	}
	if !runner.HasCommand("mv " + tempPath + " " + agentBinaryPath) {
		t.Fatalf("expected the new binary to replace the old one, got: %v", runner.Commands)
	}
	if !runner.HasCommandWithPrefix("sh -c nohup sh -c 'sleep 2 && systemctl restart satsetops-agent'") {
		t.Fatalf("expected a scheduled restart command, got: %v", runner.Commands)
	}

	// Order matters: downloading before swapping, swapping before restarting.
	downloadIdx, chmodIdx, mvIdx, restartIdx := -1, -1, -1, -1
	for i, cmd := range runner.Commands {
		switch {
		case strings.HasPrefix(cmd, "curl"):
			downloadIdx = i
		case strings.HasPrefix(cmd, "chmod"):
			chmodIdx = i
		case strings.HasPrefix(cmd, "mv"):
			mvIdx = i
		case strings.HasPrefix(cmd, "sh -c nohup"):
			restartIdx = i
		}
	}
	if !(downloadIdx < chmodIdx && chmodIdx < mvIdx && mvIdx < restartIdx) {
		t.Fatalf("expected download -> chmod -> mv -> restart order, got: %v", runner.Commands)
	}
}

func TestSelfUpdateRejectsMissingVersion(t *testing.T) {
	runner := exec.NewFakeRunner()

	if _, err := Dispatch("self_update", map[string]any{}, runner); err == nil {
		t.Fatal("expected an error when version is missing from payload")
	}
	if len(runner.Commands) != 0 {
		t.Fatalf("expected no commands to run without a version, got: %v", runner.Commands)
	}
}

func TestSelfUpdateFailsCleanlyWhenDownloadFails(t *testing.T) {
	runner := exec.NewFakeRunner()
	wantURL := downloadBaseURL + "/v0.3.1/satsetopsagent-linux-" + runtime.GOARCH
	tempPath := agentBinaryPath + ".new"
	runner.Errors["curl -fsSL -o "+tempPath+" -- "+wantURL] = errors.New("network unreachable")

	if _, err := Dispatch("self_update", map[string]any{"version": "v0.3.1"}, runner); err == nil {
		t.Fatal("expected an error when the download fails")
	}
	if runner.HasCommandWithPrefix("mv ") {
		t.Fatal("must not attempt to install a binary that failed to download")
	}
}
