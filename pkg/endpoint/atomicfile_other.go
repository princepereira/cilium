// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !windows

package endpoint

import "github.com/google/renameio/v2"

// newAtomicFile creates a temporary file in tmpDir that, on
// CloseAtomicallyReplace, is atomically renamed to filename.
func newAtomicFile(tmpDir, filename string) (atomicFile, error) {
	return renameio.TempFile(tmpDir, filename)
}
