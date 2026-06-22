package exec

import (
	"bytes"
	"os/exec"
	"strings"
)

// Runner abstracts command execution for testability
type Runner interface {
	Run(name string, args ...string) (string, error)
}

// RealRunner implements Runner using os/exec
type RealRunner struct{}

func (r *RealRunner) Run(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(stdout.String()), nil
}
