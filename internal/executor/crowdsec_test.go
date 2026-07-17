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
	runner.Outputs["bash -c DEBIAN_FRONTEND=noninteractive apt-get update"] = ""
	runner.Outputs["bash -c DEBIAN_FRONTEND=noninteractive apt-get install -y crowdsec"] = ""
	runner.Outputs["cscli hub update"] = ""
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

	if !runner.HasCommand("bash -c DEBIAN_FRONTEND=noninteractive apt-get update") {
		t.Errorf("expected apt index to be refreshed after adding the crowdsec repo")
	}
	if !runner.HasCommand("cscli hub update") {
		t.Errorf("expected hub index to be refreshed before installing collections")
	}
	if !runner.HasCommand("bash -c DEBIAN_FRONTEND=noninteractive apt-get install -y crowdsec-firewall-bouncer-iptables") {
		t.Errorf("expected bouncer install command")
	}
	if !runner.HasCommand("cscli collections install crowdsecurity/sshd --force") {
		t.Errorf("expected collection install command")
	}

	hubUpdateIdx, collectionsIdx := -1, -1
	for i, cmd := range runner.Commands {
		if cmd == "cscli hub update" {
			hubUpdateIdx = i
		}
		if cmd == "cscli collections install crowdsecurity/sshd --force" && collectionsIdx == -1 {
			collectionsIdx = i
		}
	}
	if hubUpdateIdx == -1 || collectionsIdx == -1 || hubUpdateIdx > collectionsIdx {
		t.Fatalf("expected cscli hub update to run before collections install, got order: %v", runner.Commands)
	}
}

func TestInstallCrowdsecFailsWhenHubUpdateFails(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Outputs[osReleaseCmd] = "ubuntu|"
	runner.Outputs["bash -c curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | bash"] = ""
	runner.Outputs["bash -c DEBIAN_FRONTEND=noninteractive apt-get install -y crowdsec"] = ""
	runner.Errors["cscli hub update"] = errNotFound()

	_, err := installCrowdsec(nil, runner)
	if err == nil {
		t.Fatal("expected an error when the hub index can't be refreshed")
	}
	if runner.HasCommandWithPrefix("cscli collections install") {
		t.Errorf("did not expect any collection install attempt after a failed hub update, got: %v", runner.Commands)
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
	if runner.HasCommandWithPrefix("bash -c DEBIAN_FRONTEND=noninteractive apt-get update") {
		t.Errorf("did not expect an apt-get update on RHEL, got: %v", runner.Commands)
	}
}

func TestInstallCrowdsecRefreshesAptIndexBeforeInstalling(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Outputs[osReleaseCmd] = "ubuntu|"
	runner.Outputs["bash -c curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | bash"] = ""
	runner.Outputs["bash -c DEBIAN_FRONTEND=noninteractive apt-get update"] = ""
	runner.Outputs["bash -c DEBIAN_FRONTEND=noninteractive apt-get install -y crowdsec"] = ""
	runner.Outputs["cscli hub update"] = ""
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

	updateIdx, installIdx := -1, -1
	for i, cmd := range runner.Commands {
		if cmd == "bash -c DEBIAN_FRONTEND=noninteractive apt-get update" {
			updateIdx = i
		}
		if cmd == "bash -c DEBIAN_FRONTEND=noninteractive apt-get install -y crowdsec" {
			installIdx = i
		}
	}
	if updateIdx == -1 || installIdx == -1 || updateIdx > installIdx {
		t.Fatalf("expected apt-get update to run before installing crowdsec, got order: %v", runner.Commands)
	}
}

func TestInstallCrowdsecFailsWhenAptUpdateFails(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Outputs[osReleaseCmd] = "ubuntu|"
	runner.Outputs["bash -c curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | bash"] = ""
	runner.Errors["bash -c DEBIAN_FRONTEND=noninteractive apt-get update"] = errNotFound()

	_, err := installCrowdsec(nil, runner)
	if err == nil {
		t.Fatal("expected an error when the apt index can't be refreshed")
	}
	if runner.HasCommandWithPrefix("bash -c DEBIAN_FRONTEND=noninteractive apt-get install -y crowdsec") {
		t.Errorf("did not expect crowdsec install attempt after a failed apt-get update, got: %v", runner.Commands)
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
