package executor

import (
	"github.com/satsetops/agent/internal/exec"
)

func attachDomainSsl(payload map[string]any, runner exec.Runner) (string, error) {
	return "domain ssl attached", nil
}
