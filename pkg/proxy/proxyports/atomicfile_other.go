// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package proxyports

import (
	"os"
	"path/filepath"
)

// osPendingFile is a portable atomic-file implementation backed by a temporary
// file in the destination directory that is renamed into place on commit.
type osPendingFile struct {
	f    *os.File
	path string
}

// newPendingFile creates a temporary file next to path. On non-Linux platforms
// renameio is unavailable, so we use os.CreateTemp plus os.Rename, which maps to
// an atomic replacing rename on Windows.
func newPendingFile(path string) (pendingFile, error) {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp*")
	if err != nil {
		return nil, err
	}
	return &osPendingFile{f: f, path: path}, nil
}

func (p *osPendingFile) Write(b []byte) (int, error) {
	return p.f.Write(b)
}

func (p *osPendingFile) Cleanup() error {
	name := p.f.Name()
	p.f.Close()
	return os.Remove(name)
}

func (p *osPendingFile) CloseAtomicallyReplace() error {
	name := p.f.Name()
	if err := p.f.Sync(); err != nil {
		p.f.Close()
		return err
	}
	if err := p.f.Close(); err != nil {
		return err
	}
	return os.Rename(name, p.path)
}
