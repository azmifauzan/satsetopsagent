package executor

import (
	"testing"

	"github.com/satsetops/agent/internal/exec"
)

func TestHardenFirewall(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Outputs["ufw default deny incoming"] = ""
	runner.Outputs["ufw default allow outgoing"] = ""
	runner.Outputs["ufw allow 22/tcp"] = ""
	runner.Outputs["ufw allow 80/tcp"] = ""
	runner.Outputs["ufw allow 443/tcp"] = ""
	runner.Outputs["ufw --force enable"] = ""

	_, err := hardenFirewall(nil, runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expectedCmds := []string{
		"ufw default deny incoming",
		"ufw default allow outgoing",
		"ufw allow 22/tcp",
		"ufw allow 80/tcp",
		"ufw allow 443/tcp",
		"ufw --force enable",
	}
	for _, cmd := range expectedCmds {
		if !runner.HasCommand(cmd) {
			t.Errorf("expected command %q to be executed", cmd)
		}
	}
}

func TestSetFirewallRule(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Outputs["ufw allow 8080/tcp"] = "Rule added"

	payload := map[string]any{
		"action": "allow",
		"port":   "8080/tcp",
	}

	out, err := setFirewallRule(payload, runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out != "Rule added" {
		t.Errorf("expected 'Rule added', got %q", out)
	}

	if !runner.HasCommand("ufw allow 8080/tcp") {
		t.Errorf("expected command 'ufw allow 8080/tcp' to be executed")
	}

	// Test invalid port
	payloadInvalid := map[string]any{
		"action": "allow",
		"port":   "8080; rm -rf /",
	}
	_, err = setFirewallRule(payloadInvalid, runner)
	if err == nil {
		t.Fatal("expected error for invalid port injection attempt")
	}
}
