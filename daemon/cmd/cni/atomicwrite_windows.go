// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package cni

import (
	"fmt"
	"os"
	"path/filepath"
)

// atomicWriteFile atomically writes data to the file at path with the given
// permissions. renameio is not available on Windows, so this implements the
// atomic write via a temporary file in the same directory followed by an
// os.Rename (which replaces existing files on Windows).
func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	base := filepath.Base(path)

	tmp, err := os.CreateTemp(dir, "."+base+".tmp*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Chmod(tmpName, perm); err != nil {
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename temp file: %w", err)
	}
	return nil
}
