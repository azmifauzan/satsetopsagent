// satsetopsagent/internal/distro/distro_test.go
package distro

import (
	"errors"
	"testing"

	"github.com/satsetops/agent/internal/exec"
)

const osReleaseCmd = `sh -c . /etc/os-release && printf '%s|%s' "$ID" "$ID_LIKE"`

func TestDetectDebianFamily(t *testing.T) {
	for _, osRelease := range []string{"debian|", "ubuntu|"} {
		runner := exec.NewFakeRunner()
		runner.Outputs[osReleaseCmd] = osRelease

		family, err := Detect(runner)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if family != Debian {
			t.Fatalf("expected Debian for %q, got %s", osRelease, family)
		}
	}
}

func TestDetectRHELFamily(t *testing.T) {
	for _, osRelease := range []string{"rhel|", "centos|", "rocky|", "almalinux|", "fedora|", "ol|rhel fedora"} {
		runner := exec.NewFakeRunner()
		runner.Outputs[osReleaseCmd] = osRelease

		family, err := Detect(runner)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if family != RHEL {
			t.Fatalf("expected RHEL for %q, got %s", osRelease, family)
		}
	}
}

func TestDetectArchFamily(t *testing.T) {
	for _, osRelease := range []string{"arch|", "manjaro|arch"} {
		runner := exec.NewFakeRunner()
		runner.Outputs[osReleaseCmd] = osRelease

		family, err := Detect(runner)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if family != Arch {
			t.Fatalf("expected Arch for %q, got %s", osRelease, family)
		}
	}
}

func TestDetectUnknownFamily(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Outputs[osReleaseCmd] = "opensuse-leap|suse opensuse"

	family, err := Detect(runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if family != Unknown {
		t.Fatalf("expected Unknown, got %s", family)
	}
}

func TestDetectPropagatesReadError(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Errors[osReleaseCmd] = errors.New("permission denied")

	_, err := Detect(runner)
	if err == nil {
		t.Fatal("expected an error when /etc/os-release can't be read")
	}
}

func TestCommandExists(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Outputs["sh -c command -v dnf"] = "/usr/bin/dnf"
	if !CommandExists(runner, "dnf") {
		t.Fatal("expected dnf to be reported as existing")
	}
}

func TestCommandDoesNotExist(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Errors["sh -c command -v yum"] = errors.New("not found")
	if CommandExists(runner, "yum") {
		t.Fatal("expected yum to be reported as missing")
	}
}
