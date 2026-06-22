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
