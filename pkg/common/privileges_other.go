// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !windows

package common

import (
	"fmt"
	"os"
)

// RequireRootPrivilege checks if the user running cmd is root. If not, it exits the program.
func RequireRootPrivilege(cmd string) {
	if os.Getuid() != 0 {
		fmt.Fprintf(os.Stderr, "Please run %q command(s) with root privileges.\n", cmd)
		os.Exit(1)
	}
}
