// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package endpoint

import "golang.org/x/sys/unix"

// exchangeDirectories atomically swaps the contents of oldpath and newpath
// using the Linux renameat2(2) RENAME_EXCHANGE flag.
func exchangeDirectories(oldpath, newpath string) error {
	return unix.Renameat2(unix.AT_FDCWD, oldpath, unix.AT_FDCWD, newpath, unix.RENAME_EXCHANGE)
}
