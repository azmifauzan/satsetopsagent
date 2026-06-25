package exec

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// Runner abstracts command execution for testability
type Runner interface {
	Run(name string, args ...string) (string, error)
	// RunWithStdin is Run, but pipes stdin to the process — used for
	// secrets (e.g. `docker login --password-stdin`) that shouldn't be
	// passed as a CLI argument, where they'd be visible via `ps`.
	RunWithStdin(name string, stdin string, args ...string) (string, error)
}

// RealRunner implements Runner using os/exec
type RealRunner struct{}

func (r *RealRunner) Run(name string, args ...string) (string, error) {
	return r.run(name, "", args...)
}

func (r *RealRunner) RunWithStdin(name string, stdin string, args ...string) (string, error) {
	return r.run(name, stdin, args...)
}

func (r *RealRunner) run(name string, stdin string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	err := cmd.Run()
	if err != nil {
		// Surface stderr so callers can pattern-match known-benign
		// failures (e.g. "already installed") instead of treating every
		// non-zero exit as fatal — exec's own error text is just
		// "exit status N" and drops the actual reason otherwise.
		stderrText := strings.TrimSpace(stderr.String())
		if stderrText != "" {
			return "", fmt.Errorf("%w: %s", err, stderrText)
		}
		return "", err
	}
	return strings.TrimSpace(stdout.String()), nil
}
