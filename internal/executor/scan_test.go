package executor

import (
	"encoding/json"
	"testing"

	"github.com/satsetops/agent/internal/exec"
)

func TestScanVPSCleanOnFreshImageBaseline(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Outputs["ss -tuln"] = "Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port\n" +
		"tcp   LISTEN 0      128    0.0.0.0:22          0.0.0.0:*\n" +
		"tcp   LISTEN 0      128    [::]:22             [::]:*\n"
	runner.Outputs["systemctl list-units --type=service --state=running"] = "" +
		"  ssh.service              loaded active running OpenBSD Secure Shell server\n" +
		"  cron.service             loaded active running Regular background program processing daemon\n" +
		"  systemd-journald.service loaded active running Journal Service\n" +
		"  getty@tty1.service       loaded active running Getty on tty1\n" +
		"\n" +
		"4 loaded units listed.\n"

	output, err := Dispatch("scan_vps", nil, runner)
	if err != nil {
		t.Fatalf("scan_vps: %v", err)
	}

	var report map[string]any
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		t.Fatalf("invalid report JSON: %v", err)
	}
	if report["clean"] != true {
		t.Fatalf("expected clean=true for a fresh-image baseline, got: %s", output)
	}
	if findings, _ := report["findings"].([]any); len(findings) != 0 {
		t.Fatalf("expected no findings, got: %v", findings)
	}
}

func TestScanVPSFlagsUnexpectedService(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Outputs["ss -tuln"] = "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n"
	runner.Outputs["systemctl list-units --type=service --state=running"] = "" +
		"  ssh.service    loaded active running OpenBSD Secure Shell server\n" +
		"  postgresql.service loaded active running PostgreSQL database\n"

	output, err := Dispatch("scan_vps", nil, runner)
	if err != nil {
		t.Fatalf("scan_vps: %v", err)
	}

	var report map[string]any
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		t.Fatalf("invalid report JSON: %v", err)
	}
	if report["clean"] != false {
		t.Fatalf("expected clean=false when a non-baseline service is running, got: %s", output)
	}

	findings, _ := report["findings"].([]any)
	found := false
	for _, f := range findings {
		if f == "Service postgresql.service is running" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected finding about postgresql.service, got: %v", findings)
	}
}

func TestScanVPSFlagsUnexpectedPort(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Outputs["ss -tuln"] = "" +
		"tcp LISTEN 0 128 0.0.0.0:22   0.0.0.0:*\n" +
		"tcp LISTEN 0 128 0.0.0.0:8080 0.0.0.0:*\n"
	runner.Outputs["systemctl list-units --type=service --state=running"] = "  ssh.service loaded active running OpenBSD Secure Shell server\n"

	output, err := Dispatch("scan_vps", nil, runner)
	if err != nil {
		t.Fatalf("scan_vps: %v", err)
	}

	var report map[string]any
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		t.Fatalf("invalid report JSON: %v", err)
	}
	if report["clean"] != false {
		t.Fatalf("expected clean=false when an unexpected port is listening, got: %s", output)
	}

	findings, _ := report["findings"].([]any)
	found := false
	for _, f := range findings {
		if f == "Port 8080 is already in use" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected finding about port 8080, got: %v", findings)
	}
}

// TestScanVPSCleanOnTencentCloudCVMBaseline reproduces the exact port/service
// fingerprint captured live from a stock Tencent Cloud CVM Ubuntu 24.04 test
// VPS (2026-07-03), including a second round of false positives caught only
// after a real onboarding attempt still reported "not clean": port 68 (DHCP
// client), port 323 (chrony's local NTP control socket), and
// networkd-dispatcher.service — plus satsetops-agent.service itself, which
// must never be flagged since the agent has to be running to scan at all.
// A third round added fwupd.service (Linux firmware update daemon, stock
// since before this box was ever used for testing).
func TestScanVPSCleanOnTencentCloudCVMBaseline(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Outputs["ss -tuln"] = "" +
		"udp   UNCONN 0 0    127.0.0.54:53        0.0.0.0:*\n" +
		"udp   UNCONN 0 0 127.0.0.53%lo:53        0.0.0.0:*\n" +
		"udp   UNCONN 0 0 10.11.8.173%eth0:68     0.0.0.0:*\n" +
		"udp   UNCONN 0 0    127.0.0.1:323        0.0.0.0:*\n" +
		"udp   UNCONN 0 0        [::1]:323           [::]:*\n" +
		"tcp   LISTEN 0 4096  127.0.0.54:53        0.0.0.0:*\n" +
		"tcp   LISTEN 0 4096 127.0.0.53%lo:53      0.0.0.0:*\n" +
		"tcp   LISTEN 0 4096     0.0.0.0:22        0.0.0.0:*\n" +
		"tcp   LISTEN 0 4096        [::]:22           [::]:*\n"
	runner.Outputs["systemctl list-units --type=service --state=running"] = "" +
		"  acpid.service               loaded active running ACPI event daemon\n" +
		"  chrony.service              loaded active running chrony, an NTP client/server\n" +
		"  ModemManager.service        loaded active running Modem Manager\n" +
		"  udisks2.service             loaded active running Disk Manager\n" +
		"  upower.service              loaded active running Daemon for power management\n" +
		"  tat_agent.service           loaded active running tat_agent\n" +
		"  fwupd.service               loaded active running Firmware update daemon\n" +
		"  networkd-dispatcher.service loaded active running Dispatcher daemon for systemd-networkd\n" +
		"  satsetops-agent.service     loaded active running SatSetOps VPS Agent\n" +
		"  ssh.service                 loaded active running OpenBSD Secure Shell server\n" +
		"  systemd-resolved.service    loaded active running Network Name Resolution\n" +
		"  systemd-networkd.service    loaded active running Network Configuration\n"

	output, err := Dispatch("scan_vps", nil, runner)
	if err != nil {
		t.Fatalf("scan_vps: %v", err)
	}

	var report map[string]any
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		t.Fatalf("invalid report JSON: %v", err)
	}
	if report["clean"] != true {
		t.Fatalf("expected clean=true on a stock Tencent Cloud CVM image, got: %s", output)
	}
	if findings, _ := report["findings"].([]any); len(findings) != 0 {
		t.Fatalf("expected no findings on a stock Tencent Cloud CVM image, got: %v", findings)
	}
}

func TestScanVPSAllowsOwnNginxCertbotPortsOnRescan(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Outputs["docker inspect -f {{.State.Running}} nginx-certbot"] = "true\n"
	runner.Outputs["ss -tuln"] = "" +
		"tcp LISTEN 0 128 0.0.0.0:22  0.0.0.0:*\n" +
		"tcp LISTEN 0 128 0.0.0.0:80  0.0.0.0:*\n" +
		"tcp LISTEN 0 128 0.0.0.0:443 0.0.0.0:*\n"
	runner.Outputs["systemctl list-units --type=service --state=running"] = "  ssh.service loaded active running OpenBSD Secure Shell server\n"

	output, err := Dispatch("scan_vps", nil, runner)
	if err != nil {
		t.Fatalf("scan_vps: %v", err)
	}

	var report map[string]any
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		t.Fatalf("invalid report JSON: %v", err)
	}
	if report["clean"] != true {
		t.Fatalf("expected clean=true when 80/443 are owned by our own nginx-certbot, got: %s", output)
	}
}

func TestScanVPSFlags80And443WhenNotOwnNginxCertbot(t *testing.T) {
	runner := exec.NewFakeRunner()
	// nginx-certbot inspect returns empty (not running / doesn't exist).
	runner.Outputs["ss -tuln"] = "" +
		"tcp LISTEN 0 128 0.0.0.0:22  0.0.0.0:*\n" +
		"tcp LISTEN 0 128 0.0.0.0:80  0.0.0.0:*\n" +
		"tcp LISTEN 0 128 0.0.0.0:443 0.0.0.0:*\n"

	output, err := Dispatch("scan_vps", nil, runner)
	if err != nil {
		t.Fatalf("scan_vps: %v", err)
	}

	var report map[string]any
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		t.Fatalf("invalid report JSON: %v", err)
	}
	if report["clean"] != false {
		t.Fatalf("expected clean=false when 80/443 are in use by something else, got: %s", output)
	}
}

func TestListeningPortsDedupsAndHandlesIPv6(t *testing.T) {
	out := "" +
		"tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n" +
		"tcp LISTEN 0 128 [::]:22    [::]:*\n" +
		"tcp LISTEN 0 128 0.0.0.0:80 0.0.0.0:*\n"

	ports := listeningPorts(out)
	if len(ports) != 2 {
		t.Fatalf("expected 2 distinct ports, got %v", ports)
	}
}

func TestRunningServicesSkipsHeaderAndFooterLines(t *testing.T) {
	out := "" +
		"UNIT              LOAD   ACTIVE SUB     DESCRIPTION\n" +
		"ssh.service       loaded active running OpenBSD Secure Shell server\n" +
		"\n" +
		"1 loaded units listed.\n"

	services := runningServices(out)
	if len(services) != 1 || services[0] != "ssh.service" {
		t.Fatalf("expected only ssh.service, got %v", services)
	}
}

func TestScanVPSReportsDetectedDistroFamily(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Outputs["ss -tuln"] = "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n"
	runner.Outputs["systemctl list-units --type=service --state=running"] = "  ssh.service loaded active running OpenBSD Secure Shell server\n"
	runner.Outputs[`sh -c . /etc/os-release && printf '%s|%s' "$ID" "$ID_LIKE"`] = "rocky|"

	output, err := Dispatch("scan_vps", nil, runner)
	if err != nil {
		t.Fatalf("scan_vps: %v", err)
	}

	var report map[string]any
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		t.Fatalf("invalid report JSON: %v", err)
	}
	if report["distro_family"] != "rhel" {
		t.Fatalf("expected distro_family=rhel, got: %v", report["distro_family"])
	}
	if report["distro_warning"] != "" {
		t.Fatalf("expected no warning for a known family, got: %v", report["distro_warning"])
	}
}

func TestScanVPSWarnsButStaysCleanOnUnknownDistro(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Outputs["ss -tuln"] = "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n"
	runner.Outputs["systemctl list-units --type=service --state=running"] = "  ssh.service loaded active running OpenBSD Secure Shell server\n"
	runner.Outputs[`sh -c . /etc/os-release && printf '%s|%s' "$ID" "$ID_LIKE"`] = "opensuse-leap|suse opensuse"

	output, err := Dispatch("scan_vps", nil, runner)
	if err != nil {
		t.Fatalf("scan_vps: %v", err)
	}

	var report map[string]any
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		t.Fatalf("invalid report JSON: %v", err)
	}
	if report["distro_family"] != "unknown" {
		t.Fatalf("expected distro_family=unknown, got: %v", report["distro_family"])
	}
	if report["distro_warning"] == "" {
		t.Fatal("expected a non-empty warning for an unrecognized distro")
	}
	if report["clean"] != true {
		t.Fatal("an unrecognized distro must not block onboarding — clean should stay true when nothing else is wrong")
	}
}

func TestScanVPSCleanOnStockRHELBaseline(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Outputs["ss -tuln"] = "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n"
	runner.Outputs["systemctl list-units --type=service --state=running"] = "" +
		"  sshd.service        loaded active running OpenSSH server daemon\n" +
		"  firewalld.service   loaded active running firewalld - dynamic firewall daemon\n" +
		"  auditd.service      loaded active running Security Auditing Service\n" +
		"  chronyd.service     loaded active running NTP client/server\n" +
		"  crond.service       loaded active running Command Scheduler\n" +
		"  rsyslog.service     loaded active running System Logging Service\n" +
		"  NetworkManager.service loaded active running Network Manager\n"
	runner.Outputs[`sh -c . /etc/os-release && printf '%s|%s' "$ID" "$ID_LIKE"`] = "rocky|"

	output, err := Dispatch("scan_vps", nil, runner)
	if err != nil {
		t.Fatalf("scan_vps: %v", err)
	}

	var report map[string]any
	json.Unmarshal([]byte(output), &report)
	if report["clean"] != true {
		t.Fatalf("expected clean=true on a stock RHEL-family image, got: %s", output)
	}
}

func TestScanVPSCleanOnStockArchBaseline(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Outputs["ss -tuln"] = "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n"
	runner.Outputs["systemctl list-units --type=service --state=running"] = "" +
		"  sshd.service          loaded active running OpenSSH Daemon\n" +
		"  systemd-timesyncd.service loaded active running Network Time Synchronization\n" +
		"  NetworkManager.service loaded active running Network Manager\n"
	runner.Outputs[`sh -c . /etc/os-release && printf '%s|%s' "$ID" "$ID_LIKE"`] = "arch|"

	output, err := Dispatch("scan_vps", nil, runner)
	if err != nil {
		t.Fatalf("scan_vps: %v", err)
	}

	var report map[string]any
	json.Unmarshal([]byte(output), &report)
	if report["clean"] != true {
		t.Fatalf("expected clean=true on a stock Arch image, got: %s", output)
	}
}

func TestScanVPSReportsTotalCPUAndRAM(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Outputs["ss -tuln"] = "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n"
	runner.Outputs["systemctl list-units --type=service --state=running"] = "  ssh.service loaded active running OpenBSD Secure Shell server\n"

	output, err := Dispatch("scan_vps", nil, runner)
	if err != nil {
		t.Fatalf("scan_vps: %v", err)
	}

	var report map[string]any
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		t.Fatalf("invalid report JSON: %v", err)
	}

	totalCPU, ok := report["total_cpu_cores"].(float64)
	if !ok || totalCPU < 1 {
		t.Fatalf("expected total_cpu_cores to be a positive number, got: %v", report["total_cpu_cores"])
	}

	totalRAM, ok := report["total_ram_mb"].(float64)
	if !ok || totalRAM < 1 {
		t.Fatalf("expected total_ram_mb to be a positive number, got: %v", report["total_ram_mb"])
	}

	totalDisk, ok := report["total_disk_gb"].(float64)
	if !ok || totalDisk < 1 {
		t.Fatalf("expected total_disk_gb to be a positive number, got: %v", report["total_disk_gb"])
	}
}

func TestScanVPSReportsOSName(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Outputs["ss -tuln"] = "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n"
	runner.Outputs["systemctl list-units --type=service --state=running"] = "  ssh.service loaded active running OpenBSD Secure Shell server\n"
	runner.Outputs[osReleaseCmd] = "ubuntu|"
	runner.Outputs[`sh -c . /etc/os-release && printf '%s' "$PRETTY_NAME"`] = "Ubuntu 22.04.4 LTS"

	output, err := Dispatch("scan_vps", nil, runner)
	if err != nil {
		t.Fatalf("scan_vps: %v", err)
	}

	var report map[string]any
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		t.Fatalf("invalid report JSON: %v", err)
	}

	if report["os_name"] != "Ubuntu 22.04.4 LTS" {
		t.Fatalf("expected os_name to be the PRETTY_NAME, got: %v", report["os_name"])
	}
	if report["distro_family"] != "debian" {
		t.Fatalf("expected distro_family to stay the coarse tooling family (debian), got: %v", report["distro_family"])
	}
}
