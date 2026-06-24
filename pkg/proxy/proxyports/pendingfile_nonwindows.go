// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !windows

package proxyports

import "github.com/google/renameio/v2"

type pendingFile = renameio.PendingFile

func newPendingFile(path string) (*pendingFile, error) {
	return renameio.NewPendingFile(path, renameio.WithExistingPermissions(), renameio.WithPermissions(0o600))
}
