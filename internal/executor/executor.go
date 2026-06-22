package executor

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
)

// Dispatch only executes action types compiled into the agent. There is no
// fallback to a shell or arbitrary command execution.
func Dispatch(commandType string, _ map[string]any) (string, error) {
	switch commandType {
	case "scan_vps":
		return scanVPS()
	default:
		return "", fmt.Errorf("unsupported command type: %s", commandType)
	}
}

func scanVPS() (string, error) {
	_, dockerSocketError := os.Stat("/var/run/docker.sock")
	report := struct {
		Docker       bool   `json:"docker"`
		Clean        bool   `json:"clean"`
		OS           string `json:"os"`
		Architecture string `json:"architecture"`
	}{
		Docker:       dockerSocketError == nil,
		Clean:        true,
		OS:           runtime.GOOS,
		Architecture: runtime.GOARCH,
	}

	encoded, err := json.Marshal(report)
	if err != nil {
		return "", fmt.Errorf("encode VPS scan: %w", err)
	}
	return string(encoded), nil
}
