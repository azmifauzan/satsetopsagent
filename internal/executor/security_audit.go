package executor

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/satsetops/agent/internal/distro"
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
	findings := []auditFinding{}

	family, familyErr := distro.Detect(runner)

	osRelease, _ := runner.Run("sh", "-c", ". /etc/os-release && printf '%s|%s' \"$ID\" \"$VERSION_ID\"")
	osID, osVersion, _ := strings.Cut(osRelease, "|")

	securityPending := securityUpdatesPending(runner, family)
	_, rebootErr := runner.Run("test", "-f", "/var/run/reboot-required")

	firewallActive, firewallDefaultDeny := firewallStatus(runner, family)
	if !firewallActive || !firewallDefaultDeny {
		findings = append(findings, auditFinding{"high", "firewall_not_hardened", "Firewall tidak aktif atau default incoming bukan deny", "harden_firewall", true})
	}

	ports, _ := runner.Run("ss", "-tuln")
	sshOut, _ := runner.Run("sshd", "-T")
	sshOK := containsLine(sshOut, "permitemptypasswords no") && containsLine(sshOut, "maxauthtries 4") && containsLine(sshOut, "x11forwarding no")
	if !sshOK {
		findings = append(findings, auditFinding{"medium", "ssh_baseline_missing", "Baseline SSH hardening belum lengkap", "ssh_harden", true})
	}

	// CrowdSec has no supported install path on Arch (see install_crowdsec) —
	// don't penalize the score for a gap that's a known, accepted platform
	// limitation rather than a misconfiguration.
	crowdsecApplicable := family != distro.Arch
	crowdsecActive := crowdsecApplicable && isActive(runner, "crowdsec")
	bouncerActive := crowdsecApplicable && isActive(runner, "crowdsec-firewall-bouncer")
	if crowdsecApplicable && (!crowdsecActive || !bouncerActive) {
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
	if familyErr != nil || family == distro.Unknown {
		findings = append(findings, auditFinding{"low", "distro_unrecognized", "Distro tidak dikenali — sebagian pengecekan mungkin tidak akurat", "", false})
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
		"distro_family": string(family),
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
		"crowdsec": map[string]any{
			"applicable":     crowdsecApplicable,
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

func firewallStatus(runner exec.Runner, family distro.Family) (active, defaultDeny bool) {
	switch family {
	case distro.RHEL:
		state, _ := runner.Run("firewall-cmd", "--state")
		active = strings.TrimSpace(state) == "running"
		// firewalld's public zone (SatsetOps' default) rejects anything not
		// explicitly allowed — there's no separate "default policy" line to
		// grep the way ufw has one, so "active" already implies deny-by-default.
		defaultDeny = active
	case distro.Arch:
		out, _ := runner.Run("iptables", "-L", "INPUT")
		active = strings.Contains(out, "Chain INPUT")
		defaultDeny = strings.Contains(out, "policy DROP")
	default:
		ufwStatus, _ := runner.Run("ufw", "status", "verbose")
		active = strings.Contains(ufwStatus, "Status: active")
		defaultDeny = strings.Contains(ufwStatus, "Default: deny (incoming)")
	}
	return active, defaultDeny
}

func securityUpdatesPending(runner exec.Runner, family distro.Family) int {
	var cmd string
	switch family {
	case distro.RHEL:
		cmd = "dnf -q check-update --security 2>/dev/null | grep -c ."
	case distro.Arch:
		return 0 // no security-only update classification on Arch; apt_upgrade covers the one-time case
	default:
		cmd = "apt-get -s upgrade 2>/dev/null | grep -ci '^Inst .*Security'"
	}

	out, err := runner.Run("bash", "-c", cmd)
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
