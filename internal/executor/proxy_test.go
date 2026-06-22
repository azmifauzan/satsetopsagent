package executor

import (
	"errors"
	"testing"

	"github.com/satsetops/agent/internal/exec"
)

func TestAttachDomainSSL(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Outputs["mkdir -p /etc/nginx/user_conf.d"] = ""
	runner.Outputs["mkdir -p /etc/letsencrypt"] = ""
	runner.Outputs["bash -c"] = "" // covers the echo -e write command prefix
	// Container doesn't exist initially:
	runner.Errors["docker inspect -f {{.State.Running}} nginx-certbot"] = errors.New("no such container")
	runner.Outputs["docker run"] = ""
	runner.Outputs["docker kill --signal=HUP nginx-certbot"] = ""

	payload := map[string]any{
		"domain": "example.com",
		"port":   8080,
		"email":  "admin@example.com",
	}

	res, err := attachDomainSSL(payload, runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if res != "domain example.com attached and SSL requested" {
		t.Errorf("unexpected success message: %s", res)
	}

	if !runner.HasCommand("mkdir -p /etc/nginx/user_conf.d") {
		t.Errorf("expected mkdir user_conf.d command")
	}

	if !runner.HasCommandWithPrefix("docker run") {
		t.Errorf("expected docker run command to deploy nginx-certbot")
	}

	if !runner.HasCommand("docker kill --signal=HUP nginx-certbot") {
		t.Errorf("expected docker kill SIGHUP command")
	}
}

func TestAttachDomainSSLAlreadyRunning(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Outputs["mkdir -p /etc/nginx/user_conf.d"] = ""
	runner.Outputs["mkdir -p /etc/letsencrypt"] = ""
	runner.Outputs["bash -c"] = ""
	// Container exists and running:
	runner.Outputs["docker inspect -f {{.State.Running}} nginx-certbot"] = "true"
	runner.Outputs["docker kill --signal=HUP nginx-certbot"] = ""

	payload := map[string]any{
		"domain": "example.com",
		"port":   8080,
	}

	_, err := attachDomainSSL(payload, runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if runner.HasCommandWithPrefix("docker run") {
		t.Errorf("should not run docker run if container is already running")
	}
}
