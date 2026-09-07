// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !windows

package cache

import (
	"io"

	"github.com/google/renameio/v2"
)

// pendingCheckpointFile is an atomic file writer used to persist the identity
// allocator checkpoint without partial writes.
type pendingCheckpointFile interface {
	io.Writer
	Cleanup() error
	CloseAtomicallyReplace() error
}

// newPendingCheckpointFile returns an atomic file writer backed by renameio,
// which is only available on non-Windows platforms.
func newPendingCheckpointFile(path string) (pendingCheckpointFile, error) {
	return renameio.NewPendingFile(path, renameio.WithExistingPermissions(), renameio.WithPermissions(0o600))
}
