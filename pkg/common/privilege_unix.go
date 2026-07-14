// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !windows

package common

import "os"

// hasRootPrivilege reports whether the current process runs as the root user
// (uid 0).
func hasRootPrivilege() bool {
	return os.Getuid() == 0
}
