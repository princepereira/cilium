// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package endpoint

import (
	"fmt"
	"os"
	"path/filepath"
)

// winPendingFile implements atomicFile on Windows, where renameio is not
// available. It writes to a temporary file in the same directory and renames it
// into place on CloseAtomicallyReplace (os.Rename replaces existing files on
// Windows via MoveFileEx).
type winPendingFile struct {
	*os.File
	dest string
}

// newAtomicFile creates a temporary file in tmpDir that, on
// CloseAtomicallyReplace, is renamed to filename.
func newAtomicFile(tmpDir, filename string) (atomicFile, error) {
	base := filepath.Base(filename)
	f, err := os.CreateTemp(tmpDir, "."+base+".tmp*")
	if err != nil {
		return nil, err
	}
	return &winPendingFile{File: f, dest: filename}, nil
}

// Cleanup closes and removes the temporary file if it still exists.
func (w *winPendingFile) Cleanup() error {
	name := w.File.Name()
	w.File.Close()
	err := os.Remove(name)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// CloseAtomicallyReplace flushes and closes the temporary file, then renames it
// over the destination.
func (w *winPendingFile) CloseAtomicallyReplace() error {
	if err := w.File.Sync(); err != nil {
		return fmt.Errorf("sync temp file: %w", err)
	}
	name := w.File.Name()
	if err := w.File.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(name, w.dest); err != nil {
		return fmt.Errorf("rename temp file: %w", err)
	}
	return nil
}
