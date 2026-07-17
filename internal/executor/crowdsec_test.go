package executor

import (
	"strings"
	"testing"

	"github.com/satsetops/agent/internal/exec"
)

func TestInstallCrowdsec(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Outputs[osReleaseCmd] = "ubuntu|"
	runner.Outputs["bash -c curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | bash"] = ""
	runner.Outputs["bash -c DEBIAN_FRONTEND=noninteractive apt-get install -y crowdsec"] = ""
	runner.Outputs["cscli collections install crowdsecurity/sshd --force"] = ""
	runner.Outputs["cscli collections install crowdsecurity/http-cve --force"] = ""
	runner.Outputs["mkdir -p /etc/systemd/system/crowdsec.service.d"] = ""
	runner.Outputs["bash -c echo -e '[Service]\\nMemoryHigh=150M\\nMemoryMax=250M\\nCPUQuota=20%\\n' > /etc/systemd/system/crowdsec.service.d/limits.conf"] = ""
	runner.Outputs["bash -c DEBIAN_FRONTEND=noninteractive apt-get install -y crowdsec-firewall-bouncer-iptables"] = ""
	runner.Outputs["systemctl daemon-reload"] = ""
	runner.Outputs["systemctl restart crowdsec"] = ""

	_, err := installCrowdsec(nil, runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !runner.HasCommand("bash -c DEBIAN_FRONTEND=noninteractive apt-get install -y crowdsec-firewall-bouncer-iptables") {
		t.Errorf("expected bouncer install command")
	}
	if !runner.HasCommand("cscli collections install crowdsecurity/sshd --force") {
		t.Errorf("expected collection install command")
	}
}

func TestInstallCrowdsecWhitelistsPlatformIPs(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Outputs[osReleaseCmd] = "ubuntu|"
	runner.Outputs["bash -c curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | bash"] = ""
	runner.Outputs["bash -c DEBIAN_FRONTEND=noninteractive apt-get install -y crowdsec"] = ""
	runner.Outputs["cscli collections install crowdsecurity/sshd --force"] = ""
	runner.Outputs["mkdir -p /etc/systemd/system/crowdsec.service.d"] = ""
	runner.Outputs["bash -c DEBIAN_FRONTEND=noninteractive apt-get install -y crowdsec-firewall-bouncer-iptables"] = ""
	runner.Outputs["systemctl daemon-reload"] = ""
	runner.Outputs["systemctl restart crowdsec"] = ""

	payload := map[string]any{
		"whitelist_ips": []any{"103.123.66.99", "not-an-ip", ""},
	}

	_, err := installCrowdsec(payload, runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !runner.HasCommand("cscli allowlists create satsetops-platform -d SatsetOps platform IPs") {
		t.Errorf("expected allowlist create command")
	}
	if !runner.HasCommand("cscli allowlists add satsetops-platform 103.123.66.99") {
		t.Errorf("expected valid IP to be whitelisted")
	}
	if runner.HasCommandWithPrefix("cscli allowlists add satsetops-platform not-an-ip") {
		t.Errorf("did not expect an invalid IP to be passed to cscli")
	}
}

func TestInstallCrowdsecSkipsWhitelistWhenPayloadEmpty(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Outputs[osReleaseCmd] = "ubuntu|"
	runner.Outputs["bash -c curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | bash"] = ""
	runner.Outputs["bash -c DEBIAN_FRONTEND=noninteractive apt-get install -y crowdsec"] = ""
	runner.Outputs["cscli collections install crowdsecurity/sshd --force"] = ""
	runner.Outputs["mkdir -p /etc/systemd/system/crowdsec.service.d"] = ""
	runner.Outputs["bash -c DEBIAN_FRONTEND=noninteractive apt-get install -y crowdsec-firewall-bouncer-iptables"] = ""
	runner.Outputs["systemctl daemon-reload"] = ""
	runner.Outputs["systemctl restart crowdsec"] = ""

	_, err := installCrowdsec(map[string]any{"whitelist_ips": []any{}}, runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if runner.HasCommandWithPrefix("cscli allowlists") {
		t.Errorf("did not expect any allowlist command when whitelist_ips is empty")
	}
}

func TestInstallCrowdsecOnRHELUsesRpmRepo(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Outputs[osReleaseCmd] = "rocky|"
	runner.Outputs["bash -c curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.rpm.sh | bash"] = ""
	runner.Outputs["bash -c dnf install -y crowdsec"] = ""
	runner.Outputs["cscli collections install crowdsecurity/sshd --force"] = ""
	runner.Outputs["mkdir -p /etc/systemd/system/crowdsec.service.d"] = ""
	runner.Outputs["bash -c dnf install -y crowdsec-firewall-bouncer-iptables"] = ""
	runner.Outputs["systemctl daemon-reload"] = ""
	runner.Outputs["systemctl restart crowdsec"] = ""

	_, err := installCrowdsec(nil, runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !runner.HasCommand("bash -c dnf install -y crowdsec") {
		t.Errorf("expected dnf install of crowdsec, got: %v", runner.Commands)
	}
	if !runner.HasCommand("bash -c curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.rpm.sh | bash") {
		t.Errorf("expected the rpm install script, got: %v", runner.Commands)
	}
}

func TestInstallCrowdsecSkipsOnArch(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Outputs[osReleaseCmd] = "arch|"

	output, err := installCrowdsec(nil, runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(output, "skipped") {
		t.Fatalf("expected a clear skip message, got: %s", output)
	}
	if len(runner.Commands) != 1 { // only the os-release read
		t.Fatalf("expected Arch to touch nothing else, got: %v", runner.Commands)
	}
}

func TestInstallCrowdsecPassesForceToCollectionsInstall(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Outputs[osReleaseCmd] = "ubuntu|"
	runner.Outputs["bash -c curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | bash"] = ""
	runner.Outputs["bash -c DEBIAN_FRONTEND=noninteractive apt-get install -y crowdsec"] = ""
	runner.Outputs["cscli collections install crowdsecurity/sshd --force"] = ""
	runner.Outputs["cscli collections install crowdsecurity/nginx --force"] = ""
	runner.Outputs["cscli collections install crowdsecurity/http-cve --force"] = ""
	runner.Outputs["mkdir -p /etc/systemd/system/crowdsec.service.d"] = ""
	runner.Outputs["bash -c DEBIAN_FRONTEND=noninteractive apt-get install -y crowdsec-firewall-bouncer-iptables"] = ""
	runner.Outputs["systemctl daemon-reload"] = ""
	runner.Outputs["systemctl restart crowdsec"] = ""

	_, err := installCrowdsec(nil, runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !runner.HasCommand("cscli collections install crowdsecurity/sshd --force") {
		t.Errorf("expected --force on the collections install call, got: %v", runner.Commands)
	}
}

func TestInstallCrowdsecRetriesTransientCollectionFailureThenSucceeds(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Outputs[osReleaseCmd] = "ubuntu|"
	runner.Outputs["bash -c curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | bash"] = ""
	runner.Outputs["bash -c DEBIAN_FRONTEND=noninteractive apt-get install -y crowdsec"] = ""
	runner.FailTimes["cscli collections install crowdsecurity/sshd --force"] = 2
	runner.Outputs["cscli collections install crowdsecurity/sshd --force"] = ""
	runner.Outputs["cscli collections install crowdsecurity/nginx --force"] = ""
	runner.Outputs["cscli collections install crowdsecurity/http-cve --force"] = ""
	runner.Outputs["mkdir -p /etc/systemd/system/crowdsec.service.d"] = ""
	runner.Outputs["bash -c DEBIAN_FRONTEND=noninteractive apt-get install -y crowdsec-firewall-bouncer-iptables"] = ""
	runner.Outputs["systemctl daemon-reload"] = ""
	runner.Outputs["systemctl restart crowdsec"] = ""

	_, err := installCrowdsec(nil, runner)
	if err != nil {
		t.Fatalf("expected the 3rd attempt to succeed, got error: %v", err)
	}
}
