package executor

import (
	"testing"

	"github.com/satsetops/agent/internal/exec"
)

func TestSysupdateHarden(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Outputs["apt-get install -y unattended-upgrades"] = ""
	runner.Outputs["bash -c echo -e 'Unattended-Upgrade::Allowed-Origins {\\n\\t\"${distro_id}:${distro_codename}-security\";\\n\\t// Extended Security Maintenance (ESM)\\n\\t\"${distro_id}ESMApps:${distro_codename}-apps-security\";\\n\\t\"${distro_id}ESM:${distro_codename}-infra-security\";\\n};\\nUnattended-Upgrade::Package-Blacklist {\\n};\\nUnattended-Upgrade::AutoFixInterruptedDpkg \"true\";\\nUnattended-Upgrade::MinimalSteps \"true\";\\nUnattended-Upgrade::InstallOnShutdown \"false\";\\nUnattended-Upgrade::Remove-Unused-Kernel-Packages \"true\";\\nUnattended-Upgrade::Remove-Unused-Dependencies \"true\";\\nUnattended-Upgrade::Automatic-Reboot \"false\";\\n' > /etc/apt/apt.conf.d/50unattended-upgrades"] = ""
	runner.Outputs["bash -c echo -e 'APT::Periodic::Update-Package-Lists \"1\";\\nAPT::Periodic::Unattended-Upgrade \"1\";\\n' > /etc/apt/apt.conf.d/20auto-upgrades"] = ""
	runner.Outputs["systemctl restart unattended-upgrades"] = ""

	_, err := sysupdateHarden(nil, runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !runner.HasCommand("apt-get install -y unattended-upgrades") {
		t.Errorf("expected unattended-upgrades install command")
	}
}
