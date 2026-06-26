package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/satsetops/agent/internal/api"
	"github.com/satsetops/agent/internal/auth"
	"github.com/satsetops/agent/internal/config"
	"github.com/satsetops/agent/internal/exec"
	"github.com/satsetops/agent/internal/poller"
	"github.com/satsetops/agent/internal/reporter"
	"github.com/satsetops/agent/internal/version"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	token, err := auth.Load(cfg.TokenPath, cfg.EncKey)
	if errors.Is(err, os.ErrNotExist) {
		if cfg.OneTimeToken == "" {
			return errors.New("SATSETOPS_TOKEN is required for first registration")
		}
		token, err = api.New(cfg.ServerURL, "").Register(cfg.OneTimeToken)
		if err != nil {
			return err
		}
		if err := auth.Save(cfg.TokenPath, cfg.EncKey, token); err != nil {
			return fmt.Errorf("save permanent token: %w", err)
		}
		if err := config.RemoveOneTimeToken(cfg.EnvironmentPath); err != nil {
			return fmt.Errorf("remove one-time token: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("load permanent token: %w", err)
	}

	log.Printf("satsetopsagent %s connected", version.String())
	client := api.New(cfg.ServerURL, token)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errorsChannel := make(chan error, 2)

	go func() {
		errorsChannel <- poller.Run(ctx, client, cfg.PollInterval)
	}()
	go func() {
		errorsChannel <- reportMetrics(ctx, client, clampMetricsInterval(cfg.MetricsInterval))
	}()
	go func() {
		errorsChannel <- reportTraffic(ctx, client, cfg.TrafficInterval)
	}()
	go func() {
		errorsChannel <- reportSecurity(ctx, client, cfg.SecurityInterval)
	}()

	err = <-errorsChannel
	cancel()
	if errors.Is(err, api.ErrUnauthorized) {
		log.Print("token revoked, stopping")
		return nil
	}
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

func reportMetrics(ctx context.Context, client *api.Client, interval time.Duration) error {
	for {
		metrics, err := reporter.Collect()
		if err != nil {
			log.Printf("metric collection failed: %v", err)
		} else if response, err := client.PostMetrics(metrics); errors.Is(err, api.ErrUnauthorized) {
			return api.ErrUnauthorized
		} else if err != nil {
			log.Printf("metric report failed: %v", err)
		} else if response.NextIntervalSeconds > 0 {
			interval = clampMetricsInterval(time.Duration(response.NextIntervalSeconds) * time.Second)
			if !response.MetricsEnabled {
				log.Printf("metrics ingest paused by server for %s", interval)
			}
		}

		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func clampMetricsInterval(interval time.Duration) time.Duration {
	if interval < 10*time.Second {
		return 10 * time.Second
	}
	if interval > time.Hour {
		return time.Hour
	}
	return interval
}

func reportTraffic(ctx context.Context, client *api.Client, interval time.Duration) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		traffic, err := reporter.CollectTraffic(&exec.RealRunner{})
		if err != nil {
			log.Printf("traffic collection failed: %v", err)
		} else if err := client.PostTraffic(traffic); errors.Is(err, api.ErrUnauthorized) {
			return api.ErrUnauthorized
		} else if err != nil {
			log.Printf("traffic report failed: %v", err)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func reportSecurity(ctx context.Context, client *api.Client, interval time.Duration) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		security, err := reporter.CollectSecurity(&exec.RealRunner{})
		if err != nil {
			log.Printf("security collection failed: %v", err)
		} else if err := client.PostSecurity(security); errors.Is(err, api.ErrUnauthorized) {
			return api.ErrUnauthorized
		} else if err != nil {
			log.Printf("security report failed: %v", err)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
