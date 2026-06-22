package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadUsesMachineIDAndConfiguredIntervals(t *testing.T) {
	machineID := filepath.Join(t.TempDir(), "machine-id")
	if err := os.WriteFile(machineID, []byte("stable-host-id\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SATSETOPS_MACHINE_ID_PATH", machineID)
	t.Setenv("SATSETOPS_URL", "https://example.test/")
	t.Setenv("SATSETOPS_POLL_INTERVAL", "2s")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.ServerURL != "https://example.test" || cfg.PollInterval.String() != "2s" {
		t.Fatalf("unexpected config: %+v", cfg)
	}
	if len(cfg.EncKey) != 32 {
		t.Fatalf("key length %d, want 32", len(cfg.EncKey))
	}
}

func TestRemoveOneTimeTokenPreservesOtherSettings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.env")
	contents := "SATSETOPS_URL=https://example.test\nSATSETOPS_TOKEN=secret\n"
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := RemoveOneTimeToken(path); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "secret") || !strings.Contains(string(raw), "SATSETOPS_URL") {
		t.Fatalf("unexpected environment file: %q", raw)
	}
}
