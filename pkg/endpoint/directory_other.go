// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package endpoint

import "os"

// exchangeDirectories swaps oldpath and newpath. Platforms other than Linux do
// not provide an atomic directory exchange primitive (renameat2/RENAME_EXCHANGE),
// so this falls back to a best-effort non-atomic move. The BPF datapath that
// relies on this is Linux-only, so this path is only exercised for compilation.
func exchangeDirectories(oldpath, newpath string) error {
	if err := os.RemoveAll(newpath); err != nil {
		return err
	}
	return os.Rename(oldpath, newpath)
}
