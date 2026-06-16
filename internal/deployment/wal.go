package deployment

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// BakSuffix is appended to the WAL path for the backup copy.
const BakSuffix = ".bak"

// Load reads deployment.json, transparently self-healing from the .bak copy if
// the primary file is missing or corrupt. It returns an error only when neither
// the primary nor the backup is a readable, valid WAL.
func Load(path string) (*Deployment, error) {
	d, err1 := readOne(path)
	if err1 == nil {
		return d, nil
	}
	d, err2 := readOne(path + BakSuffix)
	if err2 == nil {
		return d, nil
	}
	return nil, fmt.Errorf("deployment: no valid WAL: primary: %v; backup: %v", err1, err2)
}

func readOne(path string) (*Deployment, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var d Deployment
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, err
	}
	return &d, nil
}

// Save writes the WAL durably so a crash mid-write can never leave the device
// without a readable copy. It writes the backup first, then the primary; both
// receive the new content via a temp file that is fsync'd and atomically renamed
// into place, with the parent directory fsync'd so the rename itself is durable.
// On recovery, Load prefers the primary and falls back to the backup, so at
// worst a torn primary write is covered by an intact backup.
func (d *Deployment) Save(path string) error {
	data, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := writeFileSync(path+BakSuffix, data); err != nil {
		return fmt.Errorf("deployment: write backup: %w", err)
	}
	if err := writeFileSync(path, data); err != nil {
		return fmt.Errorf("deployment: write primary: %w", err)
	}
	return nil
}

// writeFileSync writes data to a sibling temp file, fsyncs it, atomically renames
// it over path, and fsyncs the parent directory so the rename survives a crash.
func writeFileSync(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename succeeds

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	return fsyncDir(dir)
}

func fsyncDir(dir string) error {
	df, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer df.Close()
	// Directory fsync is best-effort: some filesystems return EINVAL, which is
	// not a durability failure for the rename we already completed.
	if err := df.Sync(); err != nil && !isEINVAL(err) {
		return err
	}
	return nil
}
