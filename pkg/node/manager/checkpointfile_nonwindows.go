// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !windows

package manager

import "github.com/google/renameio/v2"

type checkpointFile = renameio.PendingFile

func newCheckpointFile(dir, path string) (*checkpointFile, error) {
	return renameio.TempFile(dir, path)
}
