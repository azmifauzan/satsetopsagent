package config

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

const (
	defaultServerURL       = "https://app.satsetops.id"
	defaultTokenPath       = "/etc/satsetops/token.enc"
	defaultEnvironmentPath = "/etc/satsetops/agent.env"
)

type Config struct {
	ServerURL        string
	OneTimeToken     string
	TokenPath        string
	EnvironmentPath  string
	EncKey           []byte
	PollInterval     time.Duration
	MetricsInterval  time.Duration
	TrafficInterval  time.Duration
	SecurityInterval time.Duration
}

func Load() (Config, error) {
	pollInterval, err := durationFromEnv("SATSETOPS_POLL_INTERVAL", 10*time.Second)
	if err != nil {
		return Config{}, err
	}
	metricsInterval, err := durationFromEnv("SATSETOPS_METRICS_INTERVAL", 30*time.Second)
	if err != nil {
		return Config{}, err
	}
	trafficInterval, err := durationFromEnv("SATSETOPS_TRAFFIC_INTERVAL", 60*time.Second)
	if err != nil {
		return Config{}, err
	}
	securityInterval, err := durationFromEnv("SATSETOPS_SECURITY_INTERVAL", 60*time.Second)
	if err != nil {
		return Config{}, err
	}

	machineID, err := os.ReadFile(valueOrDefault("SATSETOPS_MACHINE_ID_PATH", "/etc/machine-id"))
	if err != nil {
		return Config{}, fmt.Errorf("read machine ID: %w", err)
	}
	if len(strings.TrimSpace(string(machineID))) == 0 {
		return Config{}, errors.New("machine ID is empty")
	}
	key := sha256.Sum256([]byte(strings.TrimSpace(string(machineID))))

	return Config{
		ServerURL:        strings.TrimRight(valueOrDefault("SATSETOPS_URL", defaultServerURL), "/"),
		OneTimeToken:     os.Getenv("SATSETOPS_TOKEN"),
		TokenPath:        valueOrDefault("SATSETOPS_TOKEN_PATH", defaultTokenPath),
		EnvironmentPath:  valueOrDefault("SATSETOPS_ENV_PATH", defaultEnvironmentPath),
		EncKey:           key[:],
		PollInterval:     pollInterval,
		MetricsInterval:  metricsInterval,
		TrafficInterval:  trafficInterval,
		SecurityInterval: securityInterval,
	}, nil
}

func RemoveOneTimeToken(path string) error {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read environment file: %w", err)
	}

	lines := strings.Split(string(raw), "\n")
	kept := lines[:0]
	for _, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "SATSETOPS_TOKEN=") {
			continue
		}
		kept = append(kept, line)
	}

	if err := os.WriteFile(path, []byte(strings.Join(kept, "\n")), 0o600); err != nil {
		return fmt.Errorf("rewrite environment file: %w", err)
	}
	return nil
}

func durationFromEnv(name string, fallback time.Duration) (time.Duration, error) {
	value := os.Getenv(name)
	if value == "" {
		return fallback, nil
	}
	duration, err := time.ParseDuration(value)
	if err != nil || duration <= 0 {
		return 0, fmt.Errorf("%s must be a positive duration", name)
	}
	return duration, nil
}

func valueOrDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
