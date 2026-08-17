// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package proxyports

import "github.com/google/renameio/v2"

// newPendingFile uses renameio to provide atomic file replacement on Linux.
func newPendingFile(path string) (pendingFile, error) {
	return renameio.NewPendingFile(path, renameio.WithExistingPermissions(), renameio.WithPermissions(0o600))
}
