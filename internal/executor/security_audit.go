package executor

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/satsetops/agent/internal/exec"
)

type auditFinding struct {
	Severity             string `json:"severity"`
	Code                 string `json:"code"`
	Message              string `json:"message"`
	RecommendedAction    string `json:"recommended_action"`
	RequiresConfirmation bool   `json:"requires_confirmation"`
}

func securityAudit(runner exec.Runner) (string, error) {
	var findings []auditFinding

	osRelease, _ := runner.Run("sh", "-c", ". /etc/os-release && printf '%s|%s' \"$ID\" \"$VERSION_ID\"")
	osID, osVersion, _ := strings.Cut(osRelease, "|")

	securityPending := securityUpdatesPending(runner)
	_, rebootErr := runner.Run("test", "-f", "/var/run/reboot-required")

	ufwStatus, _ := runner.Run("ufw", "status", "verbose")
	firewallActive := strings.Contains(ufwStatus, "Status: active")
	firewallDefaultDeny := strings.Contains(ufwStatus, "Default: deny (incoming)")
	if !firewallActive || !firewallDefaultDeny {
		findings = append(findings, auditFinding{"high", "firewall_not_hardened", "UFW tidak aktif atau default incoming bukan deny", "harden_firewall", true})
	}

	ports, _ := runner.Run("ss", "-tuln")
	sshOut, _ := runner.Run("sshd", "-T")
	sshOK := containsLine(sshOut, "permitemptypasswords no") && containsLine(sshOut, "maxauthtries 4") && containsLine(sshOut, "x11forwarding no")
	if !sshOK {
		findings = append(findings, auditFinding{"medium", "ssh_baseline_missing", "Baseline SSH hardening belum lengkap", "ssh_harden", true})
	}

	crowdsecActive := isActive(runner, "crowdsec")
	bouncerActive := isActive(runner, "crowdsec-firewall-bouncer")
	if !crowdsecActive || !bouncerActive {
		findings = append(findings, auditFinding{"medium", "crowdsec_missing", "CrowdSec atau firewall bouncer belum aktif", "install_crowdsec", true})
	}

	dockerInfo, dockerErr := runner.Run("docker", "info")
	dockerInstalled := dockerErr == nil
	dockerHardened := true
	dockerAPIExposed := false
	if dockerInstalled {
		dockerUnit, _ := runner.Run("systemctl", "cat", "docker")
		daemonJSON, _ := runner.Run("cat", "/etc/docker/daemon.json")
		dockerAPIExposed = strings.Contains(dockerInfo+dockerUnit, "tcp://")
		dockerHardened = !dockerAPIExposed && (strings.Contains(daemonJSON, `"icc": false`) || strings.Contains(daemonJSON, `"icc":false`))
		if !dockerHardened {
			findings = append(findings, auditFinding{"medium", "docker_not_hardened", "Docker belum memakai baseline hardening SatsetOps", "docker_harden", true})
		}
	}

	if securityPending > 0 {
		findings = append(findings, auditFinding{"medium", "security_updates_pending", "Security update tersedia", "sysupdate", true})
	}
	if rebootErr == nil {
		findings = append(findings, auditFinding{"medium", "reboot_required", "VPS membutuhkan reboot untuk menyelesaikan update", "reboot_server", true})
	}

	score := auditScore(findings)
	status := "healthy"
	if score < 70 {
		status = "critical"
	} else if score < 90 {
		status = "warning"
	}

	report := map[string]any{
		"status": status,
		"score":  score,
		"os": map[string]string{
			"id":      osID,
			"version": osVersion,
		},
		"updates": map[string]any{
			"security_pending": securityPending,
			"reboot_required":  rebootErr == nil,
		},
		"firewall": map[string]bool{
			"active":                firewallActive,
			"default_incoming_deny": firewallDefaultDeny,
		},
		"open_ports": nonEmptyLines(ports),
		"ssh": map[string]bool{
			"baseline_ok": sshOK,
		},
		"crowdsec": map[string]bool{
			"active":         crowdsecActive,
			"bouncer_active": bouncerActive,
		},
		"docker": map[string]bool{
			"installed":    dockerInstalled,
			"hardened":     dockerHardened,
			"api_exposed":  dockerAPIExposed,
			"icc_disabled": dockerHardened,
		},
		"findings": findings,
	}

	encoded, err := json.Marshal(report)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

func securityUpdatesPending(runner exec.Runner) int {
	out, err := runner.Run("bash", "-c", "apt-get -s upgrade 2>/dev/null | grep -ci '^Inst .*Security'")
	if err != nil {
		return 0
	}
	out = strings.TrimSpace(out)
	if out == "" {
		return 0
	}
	count, err := strconv.Atoi(out)
	if err != nil {
		return 0
	}
	return count
}

func nonEmptyLines(out string) []string {
	out = strings.TrimSpace(out)
	if out == "" {
		return []string{}
	}
	return strings.Split(out, "\n")
}

func containsLine(out, want string) bool {
	for _, line := range strings.Split(strings.ToLower(out), "\n") {
		if strings.TrimSpace(line) == want {
			return true
		}
	}
	return false
}

func isActive(runner exec.Runner, service string) bool {
	out, err := runner.Run("systemctl", "is-active", service)
	return err == nil && strings.TrimSpace(out) == "active"
}

func auditScore(findings []auditFinding) int {
	score := 100
	for _, finding := range findings {
		switch finding.Severity {
		case "high":
			score -= 25
		case "medium":
			score -= 12
		default:
			score -= 5
		}
	}
	if score < 0 {
		return 0
	}
	return score
}
