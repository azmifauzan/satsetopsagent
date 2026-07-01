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
