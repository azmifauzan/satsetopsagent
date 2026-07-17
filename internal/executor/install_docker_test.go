package executor

import (
	"testing"

	"github.com/satsetops/agent/internal/exec"
)

func TestInstallDockerOnDebian(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Outputs[osReleaseCmd] = "ubuntu|"
	runner.Errors["sh -c command -v docker"] = errNotFound()
	runner.Outputs["bash -c DEBIAN_FRONTEND=noninteractive apt-get install -y docker.io"] = ""
	runner.Outputs["systemctl enable --now docker"] = ""

	output, err := installDocker(runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if output != "docker installed" {
		t.Fatalf("unexpected output: %s", output)
	}
	if !runner.HasCommand("bash -c DEBIAN_FRONTEND=noninteractive apt-get install -y docker.io") {
		t.Errorf("expected apt-get install docker.io command")
	}
	if !runner.HasCommand("systemctl enable --now docker") {
		t.Errorf("expected docker enable command")
	}
}

func TestInstallDockerSkipsWhenAlreadyPresent(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Outputs["sh -c command -v docker"] = "/usr/bin/docker"

	output, err := installDocker(runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if output != "docker already installed" {
		t.Fatalf("unexpected output: %s", output)
	}
	if len(runner.Commands) != 1 {
		t.Fatalf("expected only the docker-presence check, got: %v", runner.Commands)
	}
}

func TestInstallDockerOnRHEL(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Errors["sh -c command -v docker"] = errNotFound()
	runner.Outputs[osReleaseCmd] = "rocky|"
	runner.Outputs["sh -c command -v dnf"] = "/usr/bin/dnf"
	runner.Outputs["bash -c dnf install -y dnf-plugins-core"] = ""
	runner.Outputs["bash -c dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo"] = ""
	runner.Outputs["bash -c dnf install -y docker-ce docker-ce-cli containerd.io"] = ""
	runner.Outputs["systemctl enable --now docker"] = ""

	_, err := installDocker(runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !runner.HasCommand("bash -c dnf install -y dnf-plugins-core") {
		t.Errorf("expected dnf-plugins-core install command, got: %v", runner.Commands)
	}
	if !runner.HasCommand("bash -c dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo") {
		t.Errorf("expected docker-ce repo to be added, got: %v", runner.Commands)
	}
	if !runner.HasCommand("bash -c dnf install -y docker-ce docker-ce-cli containerd.io") {
		t.Errorf("expected dnf docker-ce install command, got: %v", runner.Commands)
	}
}

func TestInstallDockerOnRHELWithoutDnfUsesYum(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Errors["sh -c command -v docker"] = errNotFound()
	runner.Outputs[osReleaseCmd] = "centos|"
	runner.Errors["sh -c command -v dnf"] = errNotFound()
	runner.Outputs["bash -c yum install -y yum-utils"] = ""
	runner.Outputs["bash -c yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo"] = ""
	runner.Outputs["bash -c yum install -y docker-ce docker-ce-cli containerd.io"] = ""
	runner.Outputs["systemctl enable --now docker"] = ""

	_, err := installDocker(runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !runner.HasCommand("bash -c yum install -y yum-utils") {
		t.Errorf("expected yum-utils install command, got: %v", runner.Commands)
	}
	if !runner.HasCommand("bash -c yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo") {
		t.Errorf("expected docker-ce repo to be added via yum-config-manager, got: %v", runner.Commands)
	}
}

func TestInstallDockerOnArch(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Errors["sh -c command -v docker"] = errNotFound()
	runner.Outputs[osReleaseCmd] = "arch|"
	runner.Outputs["bash -c pacman -Sy --noconfirm docker"] = ""
	runner.Outputs["systemctl enable --now docker"] = ""

	_, err := installDocker(runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !runner.HasCommand("bash -c pacman -Sy --noconfirm docker") {
		t.Errorf("expected pacman docker install command, got: %v", runner.Commands)
	}
}

func TestInstallDockerRetriesTransientFailureThenSucceeds(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Errors["sh -c command -v docker"] = errNotFound()
	runner.Outputs[osReleaseCmd] = "ubuntu|"
	runner.FailTimes["bash -c DEBIAN_FRONTEND=noninteractive apt-get install -y docker.io"] = 2
	runner.Outputs["bash -c DEBIAN_FRONTEND=noninteractive apt-get install -y docker.io"] = ""
	runner.Outputs["systemctl enable --now docker"] = ""

	_, err := installDocker(runner)
	if err != nil {
		t.Fatalf("expected the 3rd attempt to succeed, got error: %v", err)
	}
}

func TestInstallDockerFailsAfterExhaustingRetries(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Errors["sh -c command -v docker"] = errNotFound()
	runner.Outputs[osReleaseCmd] = "ubuntu|"
	runner.Errors["bash -c DEBIAN_FRONTEND=noninteractive apt-get install -y docker.io"] = errNotFound()

	_, err := installDocker(runner)
	if err == nil {
		t.Fatal("expected an error after exhausting retries")
	}
}
