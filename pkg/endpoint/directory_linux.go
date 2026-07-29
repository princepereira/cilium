// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package endpoint

import "golang.org/x/sys/unix"

// exchangeDirectories atomically exchanges the contents of tmpDir and origDir
// using the renameat2(2) RENAME_EXCHANGE flag.
func exchangeDirectories(tmpDir, origDir string) error {
	return unix.Renameat2(unix.AT_FDCWD, tmpDir, unix.AT_FDCWD, origDir, unix.RENAME_EXCHANGE)
}
