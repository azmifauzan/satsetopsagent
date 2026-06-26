package executor

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/satsetops/agent/internal/exec"
)

func TestSecurityAuditHealthyReadOnly(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Outputs["sh -c . /etc/os-release"] = "ubuntu|24.04"
	runner.Outputs["bash -c apt-get -s upgrade"] = "0"
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
	runner.Outputs["bash -c apt-get -s upgrade"] = "2"
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
