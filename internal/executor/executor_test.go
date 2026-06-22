package executor

import (
	"encoding/json"
	"testing"
)

func TestUnknownTypeReturnsError(t *testing.T) {
	if _, err := Dispatch("totally_unknown", nil); err == nil {
		t.Fatal("expected error for unknown command type")
	}
}

func TestScanVPSReturnsJSONReport(t *testing.T) {
	output, err := Dispatch("scan_vps", nil)
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
