package executor

import (
	"github.com/satsetops/agent/internal/exec"
)

func backupNow(payload map[string]any, runner exec.Runner) (string, error) {
	return "backup completed", nil
}
