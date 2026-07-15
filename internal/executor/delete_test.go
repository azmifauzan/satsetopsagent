package executor

import (
	"errors"
	"testing"

	"github.com/satsetops/agent/internal/exec"
)

func TestDeleteAppNoDomain(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Outputs["docker rm -f myapp"] = ""

	res, err := deleteApp(map[string]any{"name": "myapp"}, runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res != "container myapp removed" {
		t.Errorf("unexpected result: %s", res)
	}
	if runner.HasCommandWithPrefix("rm -f /etc/nginx") {
		t.Errorf("did not expect vhost removal without a domain")
	}
}

func TestDeleteAppWithDomain(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Outputs["docker rm -f myapp"] = ""
	runner.Outputs["rm -f /etc/nginx/user_conf.d/example.com.conf"] = ""
	runner.Outputs["docker kill --signal=HUP nginx-certbot"] = ""

	res, err := deleteApp(map[string]any{"name": "myapp", "domain": "example.com"}, runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res != "container myapp removed, vhost for example.com deleted" {
		t.Errorf("unexpected result: %s", res)
	}
	if !runner.HasCommand("rm -f /etc/nginx/user_conf.d/example.com.conf") {
		t.Errorf("expected vhost config removal")
	}
	if !runner.HasCommand("docker kill --signal=HUP nginx-certbot") {
		t.Errorf("expected nginx-certbot reload")
	}
}

func TestDeleteAppContainerAlreadyGone(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Errors["docker rm -f myapp"] = errors.New("exit status 1: Error: No such container: myapp")

	res, err := deleteApp(map[string]any{"name": "myapp"}, runner)
	if err != nil {
		t.Fatalf("expected idempotent success, got error: %v", err)
	}
	if res != "container myapp removed" {
		t.Errorf("unexpected result: %s", res)
	}
}

func TestDeleteAppInvalidName(t *testing.T) {
	runner := exec.NewFakeRunner()
	if _, err := deleteApp(map[string]any{"name": "bad name!"}, runner); err == nil {
		t.Fatal("expected error for invalid container name")
	}
}

func TestDeleteAppInvalidDomain(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Outputs["docker rm -f myapp"] = ""
	if _, err := deleteApp(map[string]any{"name": "myapp", "domain": "not a domain"}, runner); err == nil {
		t.Fatal("expected error for invalid domain")
	}
}
