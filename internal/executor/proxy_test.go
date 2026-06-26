package executor

import (
	"testing"

	"github.com/satsetops/agent/internal/exec"
)

func TestSetupNginxProxy(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Outputs["mkdir -p /etc/nginx/user_conf.d"] = ""
	runner.Outputs["mkdir -p /etc/letsencrypt"] = ""
	// Network doesn't exist yet:
	runner.Outputs["docker network inspect satsetops-proxy"] = ""
	runner.Outputs["docker network create satsetops-proxy"] = ""
	// Container doesn't exist yet:
	runner.Outputs["docker inspect -f {{.State.Running}} nginx-certbot"] = ""
	runner.Outputs["docker run"] = ""

	payload := map[string]any{"email": "user@example.com"}

	res, err := setupNginxProxy(payload, runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res != "nginx-certbot proxy deployed and hardened" {
		t.Errorf("unexpected result: %s", res)
	}
	if !runner.HasCommandWithPrefix("docker network create") {
		t.Errorf("expected docker network create satsetops-proxy")
	}
	if !runner.HasCommandWithPrefix("docker run") {
		t.Errorf("expected docker run to deploy nginx-certbot")
	}
}

func TestSetupNginxProxyIdempotent(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Outputs["mkdir -p /etc/nginx/user_conf.d"] = ""
	runner.Outputs["mkdir -p /etc/letsencrypt"] = ""
	// Network already exists:
	runner.Outputs["docker network inspect satsetops-proxy"] = `[{"Name":"satsetops-proxy"}]`
	// Container already running:
	runner.Outputs["docker inspect -f {{.State.Running}} nginx-certbot"] = "true"

	payload := map[string]any{"email": "user@example.com"}

	if _, err := setupNginxProxy(payload, runner); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if runner.HasCommandWithPrefix("docker network create") {
		t.Errorf("should not docker network create if already exists")
	}
	if runner.HasCommandWithPrefix("docker run") {
		t.Errorf("should not docker run if already running")
	}
}

func TestSetupNginxProxyMissingEmail(t *testing.T) {
	runner := exec.NewFakeRunner()
	if _, err := setupNginxProxy(map[string]any{}, runner); err == nil {
		t.Fatal("expected error for missing email")
	}
}

func TestAttachDomainSSL(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Outputs["mkdir -p /etc/nginx/user_conf.d"] = ""
	runner.Outputs["bash -c"] = "" // writeVhostConfig uses RunWithStdin("bash", ...)
	runner.Outputs["docker kill --signal=HUP nginx-certbot"] = ""

	payload := map[string]any{
		"domain":         "example.com",
		"container_name": "my-app",
		"port":           8080,
	}

	res, err := attachDomainSSL(payload, runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res != "domain example.com attached and SSL requested" {
		t.Errorf("unexpected result: %s", res)
	}
	if !runner.HasCommand("docker kill --signal=HUP nginx-certbot") {
		t.Errorf("expected HUP reload")
	}
	// attachDomainSSL must NOT deploy the container — that's setupNginxProxy's job
	if runner.HasCommandWithPrefix("docker run") {
		t.Errorf("attachDomainSSL must not deploy nginx-certbot container")
	}
}

func TestAttachDomainSSLInvalidDomain(t *testing.T) {
	runner := exec.NewFakeRunner()
	payload := map[string]any{"domain": "not_a_domain!", "container_name": "app", "port": 80}
	if _, err := attachDomainSSL(payload, runner); err == nil {
		t.Fatal("expected error for invalid domain")
	}
}

func TestAttachDomainSSLInvalidContainerName(t *testing.T) {
	runner := exec.NewFakeRunner()
	payload := map[string]any{"domain": "example.com", "container_name": "app; rm -rf /", "port": 80}
	if _, err := attachDomainSSL(payload, runner); err == nil {
		t.Fatal("expected error for invalid container_name")
	}
}

func TestAttachDomainSSLMissingContainerName(t *testing.T) {
	runner := exec.NewFakeRunner()
	payload := map[string]any{"domain": "example.com", "port": 80}
	if _, err := attachDomainSSL(payload, runner); err == nil {
		t.Fatal("expected error for missing container_name")
	}
}
