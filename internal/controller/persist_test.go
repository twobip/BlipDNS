package controller

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// A persist failure must reach the caller, not just the logs: the change is
// live in memory but lost on restart.
func TestPersistErrorSurfaced(t *testing.T) {
	f := NewFleet(filepath.Join(t.TempDir(), "no-such-dir", "controller.yaml"))
	if _, err := f.SetQueryLogRetention(context.Background(), 24); err == nil {
		t.Fatal("SetQueryLogRetention with unwritable config: expected error, got nil")
	}
	if err := f.Remove("ghost"); err == nil {
		t.Fatal("Remove with unwritable config: expected error, got nil")
	}
	if err := f.SetAutoUpdateHours(24); err == nil {
		t.Fatal("SetAutoUpdateHours with unwritable config: expected error, got nil")
	}
}

func TestPersistSuccess(t *testing.T) {
	f := NewFleet(filepath.Join(t.TempDir(), "controller.yaml"))
	if _, err := f.SetQueryLogRetention(context.Background(), 24); err != nil {
		t.Fatalf("SetQueryLogRetention: %v", err)
	}
	if err := f.Remove("ghost"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(f.configPath), "controller.yaml")); err != nil {
		t.Fatalf("config not written: %v", err)
	}
}
