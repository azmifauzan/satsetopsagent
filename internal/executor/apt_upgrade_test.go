// satsetopsagent/internal/executor/apt_upgrade_test.go
package executor

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/satsetops/agent/internal/exec"
)

const osReleaseCmd = `sh -c . /etc/os-release && printf '%s|%s' "$ID" "$ID_LIKE"`

func TestAptUpgrade(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Outputs[osReleaseCmd] = "ubuntu|"
	runner.Outputs["bash -c DEBIAN_FRONTEND=noninteractive apt-get update"] = ""
	runner.Outputs["bash -c DEBIAN_FRONTEND=noninteractive apt-get upgrade -y"] = ""
	runner.Errors["test -f /var/run/reboot-required"] = errors.New("not required")

	output, err := aptUpgrade(nil, runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result struct {
		Upgraded       bool `json:"upgraded"`
		RebootRequired bool `json:"reboot_required"`
	}
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if !result.Upgraded || result.RebootRequired {
		t.Fatalf("unexpected result: %s", output)
	}

	if !runner.HasCommand("bash -c DEBIAN_FRONTEND=noninteractive apt-get update") {
		t.Errorf("expected apt-get update command")
	}
	if !runner.HasCommand("bash -c DEBIAN_FRONTEND=noninteractive apt-get upgrade -y") {
		t.Errorf("expected apt-get upgrade command")
	}
}

func TestAptUpgradeDetectsRebootRequired(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Outputs[osReleaseCmd] = "ubuntu|"
	runner.Outputs["bash -c DEBIAN_FRONTEND=noninteractive apt-get update"] = ""
	runner.Outputs["bash -c DEBIAN_FRONTEND=noninteractive apt-get upgrade -y"] = ""
	runner.Outputs["test -f /var/run/reboot-required"] = ""

	output, err := aptUpgrade(nil, runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result struct {
		RebootRequired bool `json:"reboot_required"`
	}
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if !result.RebootRequired {
		t.Fatalf("expected reboot_required=true, got: %s", output)
	}
}

func TestAptUpgradeFailsOnUpgradeError(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Outputs[osReleaseCmd] = "ubuntu|"
	runner.Outputs["bash -c DEBIAN_FRONTEND=noninteractive apt-get update"] = ""
	runner.Errors["bash -c DEBIAN_FRONTEND=noninteractive apt-get upgrade -y"] = errors.New("dpkg lock held")

	_, err := aptUpgrade(nil, runner)
	if err == nil {
		t.Fatal("expected error when apt-get upgrade fails")
	}
}

func TestAptUpgradeUsesDnfOnRHEL(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Outputs[osReleaseCmd] = "rocky|"
	runner.Outputs["sh -c command -v dnf"] = "/usr/bin/dnf"
	runner.Outputs["bash -c dnf upgrade -y"] = ""
	runner.Errors["test -f /var/run/reboot-required"] = errors.New("not required")

	output, err := aptUpgrade(nil, runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !runner.HasCommand("bash -c dnf upgrade -y") {
		t.Errorf("expected dnf upgrade command, got: %v", runner.Commands)
	}

	var result struct {
		Upgraded bool `json:"upgraded"`
	}
	json.Unmarshal([]byte(output), &result)
	if !result.Upgraded {
		t.Fatal("expected upgraded=true")
	}
}

func TestAptUpgradeFallsBackToYumOnRHELWithoutDnf(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Outputs[osReleaseCmd] = "centos|"
	runner.Errors["sh -c command -v dnf"] = errors.New("not found")
	runner.Outputs["bash -c yum upgrade -y"] = ""
	runner.Errors["test -f /var/run/reboot-required"] = errors.New("not required")

	_, err := aptUpgrade(nil, runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !runner.HasCommand("bash -c yum upgrade -y") {
		t.Errorf("expected yum upgrade command, got: %v", runner.Commands)
	}
}

func TestAptUpgradeUsesPacmanOnArch(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Outputs[osReleaseCmd] = "arch|"
	runner.Outputs["bash -c pacman -Syu --noconfirm"] = ""
	runner.Errors["test -f /var/run/reboot-required"] = errors.New("not required")

	_, err := aptUpgrade(nil, runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !runner.HasCommand("bash -c pacman -Syu --noconfirm") {
		t.Errorf("expected pacman upgrade command, got: %v", runner.Commands)
	}
}

func TestAptUpgradeRetriesTransientLockFailureThenSucceeds(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Outputs[osReleaseCmd] = "ubuntu|"
	runner.Outputs["bash -c DEBIAN_FRONTEND=noninteractive apt-get update"] = ""
	runner.FailTimes["bash -c DEBIAN_FRONTEND=noninteractive apt-get upgrade -y"] = 2
	runner.Outputs["bash -c DEBIAN_FRONTEND=noninteractive apt-get upgrade -y"] = ""
	runner.Errors["test -f /var/run/reboot-required"] = errors.New("not required")

	_, err := aptUpgrade(nil, runner)
	if err != nil {
		t.Fatalf("expected the 3rd attempt to succeed, got error: %v", err)
	}
}
