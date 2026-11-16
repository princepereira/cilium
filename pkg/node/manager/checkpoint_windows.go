// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package manager

import (
	"io"
	"os"
	"path/filepath"
)

// nodeCheckpointFile is an atomic file writer used to persist the node
// checkpoint without partial writes.
type nodeCheckpointFile interface {
	io.Writer
	Cleanup() error
	CloseAtomicallyReplace() error
}

// winPendingFile is a Windows implementation of an atomic file writer. It writes
// to a temporary file in the given directory and atomically renames it over the
// destination on CloseAtomicallyReplace. renameio is not available on Windows.
type winPendingFile struct {
	f    *os.File
	path string
	done bool
}

func newNodeCheckpointFile(dir, path string) (nodeCheckpointFile, error) {
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp*")
	if err != nil {
		return nil, err
	}
	return &winPendingFile{f: tmp, path: path}, nil
}

func (w *winPendingFile) Write(p []byte) (int, error) {
	return w.f.Write(p)
}

// Cleanup removes the temporary file. It is a no-op once the file has been
// atomically renamed into place.
func (w *winPendingFile) Cleanup() error {
	if w.done {
		return nil
	}
	w.done = true
	name := w.f.Name()
	w.f.Close()
	return os.Remove(name)
}

// CloseAtomicallyReplace flushes and closes the temporary file, then renames it
// over the destination path. os.Rename replaces an existing file on Windows.
func (w *winPendingFile) CloseAtomicallyReplace() error {
	if err := w.f.Sync(); err != nil {
		return err
	}
	name := w.f.Name()
	if err := w.f.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, w.path); err != nil {
		return err
	}
	w.done = true
	return nil
}
