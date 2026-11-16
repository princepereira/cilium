// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !windows

package cni

import (
	"os"

	"github.com/google/renameio/v2"
)

// atomicWriteFile atomically writes data to the file at path with the given
// permissions, using renameio on platforms that support it.
func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	return renameio.WriteFile(path, data, perm)
}
