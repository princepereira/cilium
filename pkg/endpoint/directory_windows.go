// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package endpoint

import "os"

// exchangeDirectories emulates an atomic directory exchange on platforms that
// lack renameat2(2)/RENAME_EXCHANGE. It is not atomic: the destination is
// removed and the temporary directory is moved into its place. This is a
// best-effort fallback sufficient for platforms where the BPF datapath state
// directory handling has no kernel-level atomic exchange primitive.
func exchangeDirectories(tmpDir, origDir string) error {
	if err := os.RemoveAll(origDir); err != nil {
		return err
	}
	return os.Rename(tmpDir, origDir)
}
