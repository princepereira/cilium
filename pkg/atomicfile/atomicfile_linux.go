// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package atomicfile

import (
	"os"

	"github.com/google/renameio/v2"
)

// PendingFile is an in-progress atomic file write. On Linux it wraps
// renameio.PendingFile.
type PendingFile struct {
	pf *renameio.PendingFile
}

// Write implements io.Writer.
func (p *PendingFile) Write(b []byte) (int, error) { return p.pf.Write(b) }

// Cleanup removes the temporary file if it has not been committed.
func (p *PendingFile) Cleanup() error { return p.pf.Cleanup() }

// CloseAtomicallyReplace atomically replaces the destination with the
// temporary file's contents.
func (p *PendingFile) CloseAtomicallyReplace() error { return p.pf.CloseAtomicallyReplace() }

// NewPendingFile creates a temporary file that, on CloseAtomicallyReplace,
// atomically replaces the file at path.
func NewPendingFile(path string, opts ...Option) (*PendingFile, error) {
	c := newConfig(opts)
	var ro []renameio.Option
	if c.useExisting {
		ro = append(ro, renameio.WithExistingPermissions())
	}
	if c.permSet {
		ro = append(ro, renameio.WithPermissions(c.perm))
	}
	pf, err := renameio.NewPendingFile(path, ro...)
	if err != nil {
		return nil, err
	}
	return &PendingFile{pf: pf}, nil
}

// WriteFile atomically writes data to filename with the given permissions.
func WriteFile(filename string, data []byte, perm os.FileMode) error {
	return renameio.WriteFile(filename, data, perm)
}
