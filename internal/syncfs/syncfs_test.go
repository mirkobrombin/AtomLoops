package syncfs

import (
	"os"
	"testing"
)

func TestFileFlushesTheFilesystem(t *testing.T) {
	d, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := File(d); err != nil {
		t.Fatalf("syncfs: %v", err)
	}
}
