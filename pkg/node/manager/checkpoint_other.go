// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !windows

package manager

import (
	"io"

	"github.com/google/renameio/v2"
)

// nodeCheckpointFile is an atomic file writer used to persist the node
// checkpoint without partial writes.
type nodeCheckpointFile interface {
	io.Writer
	Cleanup() error
	CloseAtomicallyReplace() error
}

// newNodeCheckpointFile returns an atomic file writer backed by renameio, which
// is only available on non-Windows platforms.
func newNodeCheckpointFile(dir, path string) (nodeCheckpointFile, error) {
	return renameio.TempFile(dir, path)
}
