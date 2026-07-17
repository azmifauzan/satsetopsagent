package executor

import (
	"errors"
	"testing"
	"time"
)

func TestWithRetrySucceedsOnFirstTry(t *testing.T) {
	calls := 0
	out, err := withRetry(3, time.Millisecond, func() (string, error) {
		calls++
		return "ok", nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out != "ok" {
		t.Fatalf("expected ok, got %q", out)
	}
	if calls != 1 {
		t.Fatalf("expected 1 call, got %d", calls)
	}
}

func TestWithRetrySucceedsAfterTransientFailures(t *testing.T) {
	calls := 0
	out, err := withRetry(3, time.Millisecond, func() (string, error) {
		calls++
		if calls < 3 {
			return "", errors.New("transient")
		}
		return "ok", nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out != "ok" {
		t.Fatalf("expected ok, got %q", out)
	}
	if calls != 3 {
		t.Fatalf("expected 3 calls, got %d", calls)
	}
}

func TestWithRetryReturnsLastErrorAfterExhausting(t *testing.T) {
	calls := 0
	_, err := withRetry(3, time.Millisecond, func() (string, error) {
		calls++
		return "", errors.New("persistent failure")
	})
	if err == nil {
		t.Fatal("expected an error after exhausting all attempts")
	}
	if err.Error() != "persistent failure" {
		t.Fatalf("expected the last error to propagate, got: %v", err)
	}
	if calls != 3 {
		t.Fatalf("expected exactly 3 attempts, got %d", calls)
	}
}

func errNotFound() error {
	return errors.New("not found")
}
