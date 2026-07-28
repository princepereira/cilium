// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package atomicfile

import (
	"os"
	"path/filepath"
)

// PendingFile is an in-progress atomic file write backed by a temporary file
// in the destination directory.
type PendingFile struct {
	f           *os.File
	path        string
	perm        os.FileMode
	useExisting bool
	committed   bool
}

// Write implements io.Writer.
func (p *PendingFile) Write(b []byte) (int, error) { return p.f.Write(b) }

// Cleanup removes the temporary file if it has not been committed.
func (p *PendingFile) Cleanup() error {
	if p.committed {
		return nil
	}
	name := p.f.Name()
	p.f.Close()
	return os.Remove(name)
}

// CloseAtomicallyReplace flushes and closes the temporary file, applies the
// requested permissions, and renames it over the destination path. os.Rename
// replaces an existing destination on both POSIX and Windows.
func (p *PendingFile) CloseAtomicallyReplace() error {
	if p.committed {
		return nil
	}
	tmpName := p.f.Name()
	if err := p.f.Sync(); err != nil {
		p.f.Close()
		return err
	}
	if err := p.f.Close(); err != nil {
		return err
	}

	perm := p.perm
	if p.useExisting {
		if fi, err := os.Stat(p.path); err == nil {
			perm = fi.Mode().Perm()
		}
	}
	if err := os.Chmod(tmpName, perm); err != nil {
		return err
	}
	if err := os.Rename(tmpName, p.path); err != nil {
		return err
	}
	p.committed = true
	return nil
}

// NewPendingFile creates a temporary file in the destination directory that,
// on CloseAtomicallyReplace, replaces the file at path.
func NewPendingFile(path string, opts ...Option) (*PendingFile, error) {
	c := newConfig(opts)
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp")
	if err != nil {
		return nil, err
	}
	return &PendingFile{
		f:           f,
		path:        path,
		perm:        c.perm,
		useExisting: c.useExisting,
	}, nil
}

// WriteFile atomically writes data to filename with the given permissions.
func WriteFile(filename string, data []byte, perm os.FileMode) error {
	pf, err := NewPendingFile(filename, WithPermissions(perm))
	if err != nil {
		return err
	}
	defer pf.Cleanup()
	if _, err := pf.Write(data); err != nil {
		return err
	}
	return pf.CloseAtomicallyReplace()
}
