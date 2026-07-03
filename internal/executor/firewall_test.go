package executor

import (
	"strings"
	"testing"

	"github.com/satsetops/agent/internal/exec"
)

func TestHardenFirewall(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Outputs[osReleaseCmd] = "ubuntu|"
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
	runner.Outputs[osReleaseCmd] = "ubuntu|"
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

func TestHardenFirewallOnDebianUsesUfw(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Outputs[osReleaseCmd] = "ubuntu|"
	for _, args := range [][]string{
		{"default", "deny", "incoming"},
		{"default", "allow", "outgoing"},
		{"allow", "22/tcp"},
		{"allow", "80/tcp"},
		{"allow", "443/tcp"},
		{"--force", "enable"},
	} {
		runner.Outputs["ufw "+strings.Join(args, " ")] = ""
	}

	_, err := hardenFirewall(nil, runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !runner.HasCommand("ufw --force enable") {
		t.Errorf("expected ufw enable command, got: %v", runner.Commands)
	}
}

func TestHardenFirewallOnRHELUsesFirewalld(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Outputs[osReleaseCmd] = "rocky|"
	runner.Outputs["systemctl enable --now firewalld"] = ""
	runner.Outputs["firewall-cmd --permanent --add-service=ssh"] = ""
	runner.Outputs["firewall-cmd --permanent --add-service=http"] = ""
	runner.Outputs["firewall-cmd --permanent --add-service=https"] = ""
	runner.Outputs["firewall-cmd --reload"] = ""

	_, err := hardenFirewall(nil, runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !runner.HasCommand("systemctl enable --now firewalld") {
		t.Errorf("expected firewalld to be enabled, got: %v", runner.Commands)
	}
	if !runner.HasCommand("firewall-cmd --reload") {
		t.Errorf("expected firewall-cmd --reload, got: %v", runner.Commands)
	}
}

func TestHardenFirewallOnArchUsesIptables(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Outputs[osReleaseCmd] = "arch|"
	runner.Outputs["sh -c command -v iptables"] = "/usr/bin/iptables"
	runner.Outputs["iptables -P INPUT DROP"] = ""
	runner.Outputs["iptables -P OUTPUT ACCEPT"] = ""
	runner.Outputs["iptables -A INPUT -i lo -j ACCEPT"] = ""
	runner.Outputs["iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT"] = ""
	runner.Outputs["iptables -A INPUT -p tcp --dport 22 -j ACCEPT"] = ""
	runner.Outputs["iptables -A INPUT -p tcp --dport 80 -j ACCEPT"] = ""
	runner.Outputs["iptables -A INPUT -p tcp --dport 443 -j ACCEPT"] = ""

	_, err := hardenFirewall(nil, runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !runner.HasCommand("iptables -P INPUT DROP") {
		t.Errorf("expected default-deny policy, got: %v", runner.Commands)
	}
}

func TestSetFirewallRuleOnRHELAddsPort(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Outputs[osReleaseCmd] = "centos|"
	runner.Outputs["firewall-cmd --permanent --add-port=8080/tcp"] = ""
	runner.Outputs["firewall-cmd --reload"] = ""

	_, err := setFirewallRule(map[string]any{"port": "8080/tcp"}, runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !runner.HasCommand("firewall-cmd --permanent --add-port=8080/tcp") {
		t.Errorf("expected add-port command, got: %v", runner.Commands)
	}
}

func TestSetFirewallRuleOnArchAddsIptablesRule(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Outputs[osReleaseCmd] = "manjaro|arch"
	runner.Outputs["iptables -A INPUT -p tcp --dport 8080 -j ACCEPT"] = ""

	_, err := setFirewallRule(map[string]any{"port": "8080"}, runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !runner.HasCommand("iptables -A INPUT -p tcp --dport 8080 -j ACCEPT") {
		t.Errorf("expected iptables allow rule, got: %v", runner.Commands)
	}
}

func TestSetFirewallRuleOnArchDenyDeletesIptablesRule(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Outputs[osReleaseCmd] = "arch|"
	runner.Outputs["iptables -D INPUT -p tcp --dport 8080 -j ACCEPT"] = ""

	_, err := setFirewallRule(map[string]any{"port": "8080", "action": "deny"}, runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !runner.HasCommand("iptables -D INPUT -p tcp --dport 8080 -j ACCEPT") {
		t.Errorf("expected iptables delete-rule command, got: %v", runner.Commands)
	}
}
