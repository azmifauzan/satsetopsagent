package executor

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/satsetops/agent/internal/exec"
)

var errNotInstalled = errors.New("not installed")

func TestSecurityAuditHealthyReadOnly(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Outputs[osReleaseCmd] = "ubuntu|"
	runner.Outputs["sh -c . /etc/os-release && printf '%s|%s' \"$ID\" \"$VERSION_ID\""] = "ubuntu|24.04"
	runner.Outputs["bash -c apt-get -s upgrade 2>/dev/null | grep -ci '^Inst .*Security'"] = "0"
	runner.Errors["test -f /var/run/reboot-required"] = errors.New("not required")
	runner.Outputs["ufw status verbose"] = "Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)"
	runner.Outputs["sshd -T"] = "permitemptypasswords no\nmaxauthtries 4\nx11forwarding no"
	runner.Outputs["systemctl is-active crowdsec"] = "active"
	runner.Outputs["systemctl is-active crowdsec-firewall-bouncer"] = "active"
	runner.Errors["docker info"] = errors.New("no docker")

	output, err := Dispatch("security_audit", nil, runner)
	if err != nil {
		t.Fatalf("security_audit: %v", err)
	}

	var report struct {
		Status   string         `json:"status"`
		Score    int            `json:"score"`
		Findings []auditFinding `json:"findings"`
	}
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if report.Status != "healthy" || report.Score != 100 || len(report.Findings) != 0 {
		t.Fatalf("unexpected report: %s", output)
	}

	for _, command := range runner.Commands {
		if strings.Contains(command, " install ") || strings.HasPrefix(command, "systemctl restart") || strings.HasPrefix(command, "systemctl reboot") || strings.HasPrefix(command, "shutdown -r") {
			t.Fatalf("audit executed mutating command: %#v", runner.Commands)
		}
	}
}

func TestSecurityAuditCriticalFindings(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Outputs[osReleaseCmd] = "ubuntu|"
	runner.Outputs["bash -c apt-get -s upgrade 2>/dev/null | grep -ci '^Inst .*Security'"] = "2"
	runner.Outputs["ufw status verbose"] = "Status: inactive"
	runner.Outputs["sshd -T"] = "permitrootlogin yes"

	output, err := Dispatch("security_audit", nil, runner)
	if err != nil {
		t.Fatalf("security_audit: %v", err)
	}

	var report struct {
		Status   string         `json:"status"`
		Findings []auditFinding `json:"findings"`
	}
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if report.Status != "critical" || len(report.Findings) == 0 {
		t.Fatalf("unexpected report: %s", output)
	}
}

func TestSecurityAuditOnDebianChecksUfw(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Outputs[osReleaseCmd] = "ubuntu|"
	runner.Outputs["sh -c . /etc/os-release && printf '%s|%s' \"$ID\" \"$VERSION_ID\""] = "ubuntu|22.04"
	runner.Outputs["ufw status verbose"] = "Status: active\nDefault: deny (incoming), allow (outgoing)\n"
	runner.Outputs["ss -tuln"] = "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n"
	runner.Outputs["sshd -T"] = "permitemptypasswords no\nmaxauthtries 4\nx11forwarding no\n"
	runner.Outputs["systemctl is-active crowdsec"] = "active"
	runner.Outputs["systemctl is-active crowdsec-firewall-bouncer"] = "active"
	runner.Errors["docker info"] = errNotInstalled
	runner.Outputs["bash -c apt-get -s upgrade 2>/dev/null | grep -ci '^Inst .*Security'"] = "0"
	runner.Errors["test -f /var/run/reboot-required"] = errNotInstalled

	output, err := securityAudit(runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var report map[string]any
	json.Unmarshal([]byte(output), &report)
	firewall := report["firewall"].(map[string]any)
	if firewall["active"] != true {
		t.Fatalf("expected firewall.active=true, got: %s", output)
	}
}

func TestSecurityAuditOnRHELChecksFirewalld(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Outputs[osReleaseCmd] = "rocky|"
	runner.Outputs["sh -c . /etc/os-release && printf '%s|%s' \"$ID\" \"$VERSION_ID\""] = "rocky|9"
	runner.Outputs["firewall-cmd --state"] = "running"
	runner.Outputs["firewall-cmd --list-all"] = "public (active)\n  target: default\n"
	runner.Outputs["ss -tuln"] = "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n"
	runner.Outputs["sshd -T"] = "permitemptypasswords no\nmaxauthtries 4\nx11forwarding no\n"
	runner.Errors["docker info"] = errNotInstalled
	runner.Outputs["bash -c dnf -q check-update --security 2>/dev/null | grep -c ."] = "0"
	runner.Errors["test -f /var/run/reboot-required"] = errNotInstalled

	output, err := securityAudit(runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var report map[string]any
	json.Unmarshal([]byte(output), &report)
	firewall := report["firewall"].(map[string]any)
	if firewall["active"] != true {
		t.Fatalf("expected firewall.active=true for a running firewalld, got: %s", output)
	}
	crowdsecFindings := report["crowdsec"].(map[string]any)
	if crowdsecFindings["applicable"] != true {
		t.Fatalf("expected crowdsec to be applicable on RHEL, got: %s", output)
	}
}

func TestSecurityAuditOnArchSkipsCrowdsecFindings(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Outputs[osReleaseCmd] = "arch|"
	runner.Outputs["sh -c . /etc/os-release && printf '%s|%s' \"$ID\" \"$VERSION_ID\""] = "arch|"
	runner.Outputs["sh -c command -v iptables"] = "/usr/bin/iptables"
	runner.Outputs["iptables -L INPUT"] = "Chain INPUT (policy DROP)\n"
	runner.Outputs["ss -tuln"] = "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n"
	runner.Outputs["sshd -T"] = "permitemptypasswords no\nmaxauthtries 4\nx11forwarding no\n"
	runner.Errors["docker info"] = errNotInstalled
	runner.Errors["test -f /var/run/reboot-required"] = errNotInstalled

	output, err := securityAudit(runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var report map[string]any
	json.Unmarshal([]byte(output), &report)
	crowdsecFindings := report["crowdsec"].(map[string]any)
	if crowdsecFindings["applicable"] != false {
		t.Fatalf("expected crowdsec.applicable=false on Arch, got: %s", output)
	}
	for _, f := range report["findings"].([]any) {
		finding := f.(map[string]any)
		if finding["code"] == "crowdsec_missing" {
			t.Fatalf("did not expect a crowdsec_missing finding on Arch, got: %s", output)
		}
	}
}
