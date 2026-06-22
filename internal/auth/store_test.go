package auth

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "token.enc")
	key := []byte("0123456789abcdef0123456789abcdef")

	if err := Save(path, key, "secret-token"); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := Load(path, key)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got != "secret-token" {
		t.Fatalf("got %q, want secret-token", got)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode is %o, want 600", info.Mode().Perm())
	}
}

func TestLoadRejectsTruncatedCiphertext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token.enc")
	if err := os.WriteFile(path, []byte("YQ=="), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Load(path, []byte("0123456789abcdef0123456789abcdef")); err == nil {
		t.Fatal("expected truncated ciphertext error")
	}
}
