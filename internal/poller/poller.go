package poller

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/satsetops/agent/internal/api"
	"github.com/satsetops/agent/internal/executor"
)

type Client interface {
	Poll() ([]api.Command, error)
	PostResult(id int, success bool, output string, exitCode int) error
	PostMetrics(metrics api.Metrics) error
}

func RunOnce(client Client) error {
	commands, err := client.Poll()
	if err != nil {
		return err
	}

	for _, command := range commands {
		output, executeError := executor.Dispatch(command.Type, command.Payload)
		success := executeError == nil
		exitCode := 0
		if executeError != nil {
			output = executeError.Error()
			exitCode = 1
		}
		if err := client.PostResult(command.ID, success, output, exitCode); err != nil {
			return err
		}
	}
	return nil
}

func Run(ctx context.Context, client Client, interval time.Duration) error {
	if interval <= 0 {
		return fmt.Errorf("poll interval must be positive")
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		if err := RunOnce(client); err != nil {
			if errors.Is(err, api.ErrUnauthorized) {
				return api.ErrUnauthorized
			}
			log.Printf("command poll failed: %v", err)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
