package executor

import (
	"errors"
	"testing"

	"github.com/satsetops/agent/internal/exec"
)

func TestCollectLogs(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Outputs["docker logs --tail 50 test-app"] = "log-line-1\nlog-line-2"

	payload := map[string]any{
		"name": "test-app",
		"tail": 50,
	}

	logs, err := collectLogs(payload, runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if logs != "log-line-1\nlog-line-2" {
		t.Errorf("expected logs text, got %s", logs)
	}

	if !runner.HasCommand("docker logs --tail 50 test-app") {
		t.Errorf("expected docker logs command")
	}
}

func TestCollectLogsHostSource(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Outputs["tail -n 100 -- /var/log/satsetops/nginx/error.log"] = "[emerg] some real error"

	logs, err := collectLogs(map[string]any{"source": "nginx-error"}, runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if logs != "[emerg] some real error" {
		t.Errorf("unexpected output: %s", logs)
	}
}

func TestCollectLogsUnknownSource(t *testing.T) {
	runner := exec.NewFakeRunner()
	if _, err := collectLogs(map[string]any{"source": "bogus"}, runner); err == nil {
		t.Fatal("expected error for unknown log source")
	}
}

func TestCollectLogsLetsencryptViaDockerCp(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Outputs["docker cp nginx-certbot:/var/log/letsencrypt/letsencrypt.log "] = ""
	runner.Outputs["tail -n 100 -- /tmp/satsetops-letsencrypt-log-"] = "urn:ietf:params:acme:error:rateLimited"

	logs, err := collectLogs(map[string]any{"source": "letsencrypt"}, runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if logs != "urn:ietf:params:acme:error:rateLimited" {
		t.Errorf("unexpected output: %s", logs)
	}
	if !runner.HasCommandWithPrefix("docker cp nginx-certbot:/var/log/letsencrypt/letsencrypt.log ") {
		t.Errorf("expected a docker cp of the letsencrypt log")
	}
	if !runner.HasCommandWithPrefix("rm -f /tmp/satsetops-letsencrypt-log-") {
		t.Errorf("expected the temp copy to be cleaned up")
	}
}

func TestCollectLogsLetsencryptCpFailure(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Errors["docker cp nginx-certbot:/var/log/letsencrypt/letsencrypt.log "] = errors.New("exit status 1: Error: No such container:path")

	if _, err := collectLogs(map[string]any{"source": "letsencrypt"}, runner); err == nil {
		t.Fatal("expected error when docker cp fails")
	}
}

func TestCollectLogsLetsencryptInvalidName(t *testing.T) {
	runner := exec.NewFakeRunner()
	if _, err := collectLogs(map[string]any{"source": "letsencrypt", "name": "bad name!"}, runner); err == nil {
		t.Fatal("expected error for invalid container name")
	}
}
