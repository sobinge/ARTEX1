package server

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectProxyGuardShims(t *testing.T) {
	dir := t.TempDir()
	// fake wrapper + two links pointing at it
	script := filepath.Join(dir, "proxy-guard-run.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"nmap", "httpx"} {
		if err := os.Symlink(script, filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	// a normal binary must not be counted
	if err := os.WriteFile(filepath.Join(dir, "curl"), []byte("x"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+"/usr/bin")
	dirs, count := detectProxyGuardShims()
	if count != 2 {
		t.Fatalf("count = %d, want 2", count)
	}
	if len(dirs) != 1 || dirs[0] != dir {
		t.Fatalf("dirs = %v", dirs)
	}
}

func TestDetectProxyGuardShimsNone(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	if _, count := detectProxyGuardShims(); count != 0 {
		t.Fatalf("count = %d, want 0", count)
	}
}
