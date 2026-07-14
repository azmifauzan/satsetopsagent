package reporter

import (
	"errors"
	"testing"
)

func TestCollectSSLErrors_DetectsChallengeFailed(t *testing.T) {
	fakeLogs := `2026-07-14 10:00:00 Requesting certificate for example.com
2026-07-14 10:00:05 Challenge failed for domain example.com
2026-07-14 10:00:06 http-01 challenge did not pass
`
	runner := &fakeRunner{
		runFunc: func(cmd string, args ...string) (string, error) {
			if cmd == "docker" && args[0] == "logs" {
				return fakeLogs, nil
			}
			return "", errors.New("unexpected command")
		},
	}

	errorsList, err := CollectSSLErrors(runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(errorsList) != 1 {
		t.Fatalf("expected 1 ssl error, got %d", len(errorsList))
	}
	if errorsList[0].Domain != "example.com" {
		t.Fatalf("expected domain example.com, got %s", errorsList[0].Domain)
	}
}

func TestCollectSSLErrors_Deduplicates(t *testing.T) {
	fakeLogs := `Challenge failed for domain a.com
Challenge failed for domain a.com
Challenge failed for domain b.com
`
	runner := &fakeRunner{
		runFunc: func(cmd string, args ...string) (string, error) {
			return fakeLogs, nil
		},
	}

	errorsList, err := CollectSSLErrors(runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(errorsList) != 2 {
		t.Fatalf("expected 2 unique domains, got %d", len(errorsList))
	}
}

func TestCollectSSLErrors_NoContainerReturnsNilNoError(t *testing.T) {
	runner := &fakeRunner{
		runFunc: func(cmd string, args ...string) (string, error) {
			return "", errors.New("No such container: nginx-certbot")
		},
	}

	errorsList, err := CollectSSLErrors(runner)
	if err != nil {
		t.Fatalf("expected no error when container missing, got %v", err)
	}
	if errorsList != nil {
		t.Fatalf("expected nil errors list, got %v", errorsList)
	}
}

func TestCollectSSLErrors_NoFailuresReturnsEmpty(t *testing.T) {
	runner := &fakeRunner{
		runFunc: func(cmd string, args ...string) (string, error) {
			return "2026-07-14 10:00:00 Certificate obtained successfully\n", nil
		},
	}

	errorsList, err := CollectSSLErrors(runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(errorsList) != 0 {
		t.Fatalf("expected 0 ssl errors, got %d", len(errorsList))
	}
}
