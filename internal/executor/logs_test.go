package executor

import (
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

func TestCollectLogsLetsencryptSucceedsFirstTry(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Outputs["docker start nginx-certbot"] = ""
	runner.Outputs["docker exec nginx-certbot tail -n 100 /var/log/letsencrypt/letsencrypt.log"] = "urn:ietf:params:acme:error:rateLimited"

	logs, err := collectLogs(map[string]any{"source": "letsencrypt"}, runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if logs != "urn:ietf:params:acme:error:rateLimited" {
		t.Errorf("unexpected output: %s", logs)
	}
	if !runner.HasCommand("docker start nginx-certbot") {
		t.Errorf("expected the container to be started first")
	}
}

func TestCollectLogsLetsencryptDefaultNameIsInvalidNeverHappens(t *testing.T) {
	runner := exec.NewFakeRunner()
	if _, err := collectLogs(map[string]any{"source": "letsencrypt", "name": "bad name!"}, runner); err == nil {
		t.Fatal("expected error for invalid container name")
	}
}
