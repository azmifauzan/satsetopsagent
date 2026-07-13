package executor

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/satsetops/agent/internal/distro"
	"github.com/satsetops/agent/internal/exec"
	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/mem"
)

// basePortsAllowed are the ports a freshly-imaged cloud VPS is expected to
// have listening. Anything else found by `ss -tuln` is reported as a finding
// rather than assumed safe — this is deliberately an allow-list, not a
// blacklist of "known bad" software, so it catches things a blacklist would
// miss (postgres, php-fpm, random custom panels, etc).
var basePortsAllowed = map[string]bool{
	"22":  true, // sshd
	"53":  true, // systemd-resolved's DNS stub listener, on by default on stock Ubuntu 20.04+
	"68":  true, // DHCP client (systemd-networkd/dhclient) on the primary interface
	"323": true, // chrony's local NTP control socket (chronyc talks to chronyd here)
}

// baseServicesAllowed are systemd services present on a normal, unmodified
// cloud image (Ubuntu/Debian minimal images plus the major cloud providers'
// guest agents). Not exhaustive — extend as false positives turn up on real
// images — but far more reliable than matching a short list of panel names.
var baseServicesAllowed = map[string]bool{
	"ssh.service":                   true,
	"sshd.service":                  true,
	"cron.service":                  true,
	"atd.service":                   true,
	"systemd-journald.service":      true,
	"systemd-logind.service":        true,
	"systemd-networkd.service":      true,
	"systemd-resolved.service":      true,
	"systemd-timesyncd.service":     true,
	"systemd-udevd.service":         true,
	"systemd-user-sessions.service": true,
	"networking.service":            true,
	"resolvconf.service":            true,
	"dbus.service":                  true,
	"polkit.service":                true,
	"rsyslog.service":               true,
	"unattended-upgrades.service":   true,
	"snapd.service":                 true,
	"snapd.seeded.service":          true,
	"irqbalance.service":            true,
	"multipathd.service":            true,
	"e2scrub_reap.service":          true,
	"packagekit.service":            true,
	"accounts-daemon.service":       true,
	"apport.service":                true,
	"ufw.service":                   true,
	"chrony.service":                true,
	"docker.service":                true,
	"containerd.service":            true,
	"cloud-init.service":            true,
	"cloud-init-local.service":      true,
	"cloud-config.service":          true,
	"cloud-final.service":           true,
	"acpid.service":                 true,
	"ModemManager.service":          true,
	"udisks2.service":               true,
	"upower.service":                true,
	"fwupd.service":                 true,
	"networkd-dispatcher.service":   true,
	// RHEL-family (CentOS/Rocky/AlmaLinux/Fedora) baseline.
	"firewalld.service":      true,
	"auditd.service":         true,
	"chronyd.service":        true,
	"crond.service":          true,
	"NetworkManager.service": true,
	"sssd.service":           true,
	"tuned.service":          true,
	"restraintd.service":     true,
	"kdump.service":          true,
	// The agent has to be running to perform this scan at all — it must
	// never flag itself as an unexpected finding.
	"satsetops-agent.service": true,
	// Cloud provider guest agents.
	"qemu-guest-agent.service":      true,
	"open-vm-tools.service":         true,
	"walinuxagent.service":          true,
	"google-guest-agent.service":    true,
	"google-osconfig-agent.service": true,
	"amazon-ssm-agent.service":      true,
	"tat_agent.service":             true, // Tencent Cloud (CVM) guest agent
}

// baseServicePrefixesAllowed covers templated units (name@instance.service).
var baseServicePrefixesAllowed = []string{
	"getty@",
	"serial-getty@",
	"user@",
}

func scanVPS(runner exec.Runner) (string, error) {
	_, dockerSocketError := os.Stat("/var/run/docker.sock")

	clean := true
	var findings []string

	// Our own nginx-certbot proxy legitimately owns 80/443 on a re-scan
	// (e.g. after the user reinstalls the OS and re-runs setup) — don't
	// flag those two ports again in that case.
	nginxRunning, _ := runner.Run("docker", "inspect", "-f", "{{.State.Running}}", "nginx-certbot")
	nginxAlreadySetup := strings.TrimSpace(nginxRunning) == "true"

	if out, err := runner.Run("ss", "-tuln"); err == nil {
		for _, port := range listeningPorts(out) {
			if basePortsAllowed[port] {
				continue
			}
			if nginxAlreadySetup && (port == "80" || port == "443") {
				continue
			}
			clean = false
			findings = append(findings, fmt.Sprintf("Port %s is already in use", port))
		}
	}

	if out, err := runner.Run("systemctl", "list-units", "--type=service", "--state=running"); err == nil {
		for _, service := range runningServices(out) {
			if isBaselineService(service) {
				continue
			}
			clean = false
			findings = append(findings, fmt.Sprintf("Service %s is running", service))
		}
	}

	if findings == nil {
		findings = []string{}
	}

	family, familyErr := distro.Detect(runner)
	distroWarning := ""
	if familyErr != nil || family == distro.Unknown {
		distroWarning = "Distro tidak dikenali — SatsetOps mendukung Debian/Ubuntu, RHEL-family (CentOS/Rocky/AlmaLinux/Fedora), dan Arch/Manjaro. Beberapa langkah hardening mungkin gagal atau perlu ditangani manual."
	}

	// A VPS's core/RAM count doesn't change post-provision, so this is
	// reported once here rather than on every metrics tick. Best-effort: if
	// gopsutil can't read it, omit the field entirely (omitempty) rather
	// than reporting a literal 0 — a real VPS never has 0 cores/0 MB RAM, so
	// 0 here only ever means "couldn't read it". The web side's `?? $server
	// ->total_cpu_cores` fallback only preserves the previous known-good
	// value when the JSON key is absent; a reported 0 would overwrite it
	// with a value that then poisons every capacity check on that server.
	totalCPUCores, _ := cpu.Counts(true)
	var totalRAMMB uint64
	if vm, err := mem.VirtualMemory(); err == nil {
		totalRAMMB = vm.Total / 1024 / 1024
	}

	report := struct {
		Docker        bool     `json:"docker"`
		Clean         bool     `json:"clean"`
		Findings      []string `json:"findings"`
		OS            string   `json:"os"`
		Architecture  string   `json:"architecture"`
		DistroFamily  string   `json:"distro_family"`
		DistroWarning string   `json:"distro_warning"`
		TotalCPUCores int      `json:"total_cpu_cores,omitempty"`
		TotalRAMMB    uint64   `json:"total_ram_mb,omitempty"`
	}{
		Docker:        dockerSocketError == nil,
		Clean:         clean,
		Findings:      findings,
		OS:            runtime.GOOS,
		Architecture:  runtime.GOARCH,
		DistroFamily:  string(family),
		DistroWarning: distroWarning,
		TotalCPUCores: totalCPUCores,
		TotalRAMMB:    totalRAMMB,
	}

	encoded, err := json.Marshal(report)
	if err != nil {
		return "", fmt.Errorf("encode VPS scan: %w", err)
	}
	return string(encoded), nil
}

func isBaselineService(service string) bool {
	if baseServicesAllowed[service] {
		return true
	}
	for _, prefix := range baseServicePrefixesAllowed {
		if strings.HasPrefix(service, prefix) {
			return true
		}
	}
	return false
}

// listeningPorts extracts the distinct set of local ports from `ss -tuln`
// output, e.g. "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*" -> "22". Handles both
// IPv4 (0.0.0.0:22) and IPv6 ([::]:22) local-address formats.
func listeningPorts(ssOutput string) []string {
	seen := map[string]bool{}
	var ports []string

	for _, line := range strings.Split(ssOutput, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		localAddr := fields[4]
		idx := strings.LastIndex(localAddr, ":")
		if idx == -1 {
			continue
		}
		port := localAddr[idx+1:]
		if port == "" || port == "*" {
			continue
		}
		if !seen[port] {
			seen[port] = true
			ports = append(ports, port)
		}
	}

	return ports
}

// runningServices extracts unit names from `systemctl list-units
// --type=service --state=running` output, skipping the header/footer lines
// systemctl prints around the table.
func runningServices(systemctlOutput string) []string {
	var services []string

	for _, line := range strings.Split(systemctlOutput, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		name := strings.TrimPrefix(fields[0], "●")
		name = strings.TrimSpace(name)
		if strings.HasSuffix(name, ".service") {
			services = append(services, name)
		}
	}

	return services
}
