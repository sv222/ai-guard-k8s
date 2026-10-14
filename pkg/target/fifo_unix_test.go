//go:build unix

package target

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestFromDirSkipsNamedPipe(t *testing.T) {
	dir := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(dir, "pipe.yaml"), 0o644); err != nil {
		t.Skip("mkfifo not available:", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ok.yaml"), []byte("apiVersion: v1\nkind: Service\nmetadata:\n  name: s\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	done := make(chan DirScan, 1)
	go func() {
		ds, _ := FromDir(dir)
		done <- ds
	}()
	select {
	case ds := <-done:
		if len(ds.Services) != 1 || len(ds.Warnings) != 1 {
			t.Errorf("services=%d warnings=%v", len(ds.Services), ds.Warnings)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("FromDir blocked on a named pipe")
	}
}
