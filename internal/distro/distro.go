// satsetopsagent/internal/distro/distro.go
package distro

import (
	"fmt"
	"strings"

	"github.com/satsetops/agent/internal/exec"
)

// Family is a distro's package-manager/init family, used to pick the right
// commands in every executor that touches system packages or the firewall.
type Family string

const (
	Debian  Family = "debian"
	RHEL    Family = "rhel"
	Arch    Family = "arch"
	Unknown Family = "unknown"
)

// Detect reads /etc/os-release and classifies the host into one of the
// supported families via its ID and ID_LIKE fields. Returns Unknown (not an
// error) for anything not recognized — callers decide whether that's fatal
// for their specific action; scan_vps surfaces it as a warning rather than
// blocking onboarding.
func Detect(runner exec.Runner) (Family, error) {
	out, err := runner.Run("sh", "-c", `. /etc/os-release && printf '%s|%s' "$ID" "$ID_LIKE"`)
	if err != nil {
		return Unknown, fmt.Errorf("read /etc/os-release: %w", err)
	}

	id, idLike, _ := strings.Cut(out, "|")
	id = strings.ToLower(strings.TrimSpace(id))
	idLike = strings.ToLower(idLike)

	switch {
	case id == "debian" || id == "ubuntu" || strings.Contains(idLike, "debian"):
		return Debian, nil
	case id == "rhel" || id == "centos" || id == "rocky" || id == "almalinux" || id == "fedora" ||
		strings.Contains(idLike, "rhel") || strings.Contains(idLike, "fedora"):
		return RHEL, nil
	case id == "arch" || id == "manjaro" || strings.Contains(idLike, "arch"):
		return Arch, nil
	default:
		return Unknown, nil
	}
}

// CommandExists reports whether name is on the host's PATH.
func CommandExists(runner exec.Runner, name string) bool {
	_, err := runner.Run("sh", "-c", "command -v "+name)
	return err == nil
}
