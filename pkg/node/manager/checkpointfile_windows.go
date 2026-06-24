// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package manager

import (
	"os"
	"path/filepath"
)

type checkpointFile struct {
	*os.File
	tmpPath   string
	finalPath string
}

func newCheckpointFile(dir, path string) (*checkpointFile, error) {
	f, err := os.CreateTemp(dir, filepath.Base(path)+".*")
	if err != nil {
		return nil, err
	}
	return &checkpointFile{File: f, tmpPath: f.Name(), finalPath: path}, nil
}

func (f *checkpointFile) Cleanup() {
	_ = f.File.Close()
	_ = os.Remove(f.tmpPath)
}

func (f *checkpointFile) CloseAtomicallyReplace() error {
	if err := f.File.Close(); err != nil {
		return err
	}
	return os.Rename(f.tmpPath, f.finalPath)
}
