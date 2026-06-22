package executor

import (
	"encoding/json"
	"testing"

	"github.com/satsetops/agent/internal/exec"
)

func TestUnknownTypeReturnsError(t *testing.T) {
	runner := exec.NewFakeRunner()
	if _, err := Dispatch("totally_unknown", nil, runner); err == nil {
		t.Fatal("expected error for unknown command type")
	}
}

// deploy_app/restart_container/stop_container/attach_domain_ssl/collect_logs/backup_now
// are Phase 3+ scope and must stay rejected until real executors exist — a
// fake "success" stub would lie to the orchestrator about work being done.
func TestPhase3PlusTypesRejected(t *testing.T) {
	runner := exec.NewFakeRunner()
	for _, commandType := range []string{
		"deploy_app", "restart_container", "stop_container",
		"attach_domain_ssl", "collect_logs", "backup_now",
	} {
		if _, err := Dispatch(commandType, nil, runner); err == nil {
			t.Errorf("expected %q to be rejected as unimplemented", commandType)
		}
	}
}

func TestScanVPSReturnsJSONReport(t *testing.T) {
	runner := exec.NewFakeRunner()
	output, err := Dispatch("scan_vps", nil, runner)
	if err != nil {
		t.Fatalf("scan_vps: %v", err)
	}
	var report map[string]any
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		t.Fatalf("invalid report JSON: %v", err)
	}
	if report["clean"] != true {
		t.Fatalf("unexpected report: %s", output)
	}
}
