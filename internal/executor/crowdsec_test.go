package executor

import (
	"testing"

	"github.com/satsetops/agent/internal/exec"
)

func TestInstallCrowdsec(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Outputs["bash -c curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | bash"] = ""
	runner.Outputs["apt-get install -y crowdsec"] = ""
	runner.Outputs["cscli collections install crowdsecurity/sshd"] = ""
	runner.Outputs["cscli collections install crowdsecurity/http-cve"] = ""
	runner.Outputs["mkdir -p /etc/systemd/system/crowdsec.service.d"] = ""
	runner.Outputs["bash -c echo -e '[Service]\\nMemoryHigh=150M\\nMemoryMax=250M\\nCPUQuota=20%\\n' > /etc/systemd/system/crowdsec.service.d/limits.conf"] = ""
	runner.Outputs["apt-get install -y crowdsec-firewall-bouncer-iptables"] = ""
	runner.Outputs["systemctl daemon-reload"] = ""
	runner.Outputs["systemctl restart crowdsec"] = ""

	_, err := installCrowdsec(nil, runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !runner.HasCommand("apt-get install -y crowdsec-firewall-bouncer-iptables") {
		t.Errorf("expected bouncer install command")
	}
	if !runner.HasCommand("cscli collections install crowdsecurity/sshd") {
		t.Errorf("expected collection install command")
	}
}
