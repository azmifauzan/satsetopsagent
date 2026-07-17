package executor

import "time"

// retryDelayOverride, when non-zero, replaces every withRetry delay. Set
// only by tests (see main_test.go's TestMain) — production always uses the
// delay each call site passes explicitly.
var retryDelayOverride time.Duration

// withRetry runs fn up to attempts times, sleeping delay between attempts,
// for the transient failures hardening executors actually hit in
// production (dpkg lock held by cloud-init at boot, a network blip
// fetching a package index) — not a generic resilience layer, scoped only
// to the handful of external calls inside hardening executors that are
// known to be safely re-runnable.
func withRetry(attempts int, delay time.Duration, fn func() (string, error)) (string, error) {
	if retryDelayOverride > 0 {
		delay = retryDelayOverride
	}

	var lastErr error
	for i := 0; i < attempts; i++ {
		out, err := fn()
		if err == nil {
			return out, nil
		}
		lastErr = err
		if i < attempts-1 {
			time.Sleep(delay)
		}
	}
	return "", lastErr
}
