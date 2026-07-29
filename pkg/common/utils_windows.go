// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package common

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// RequireRootPrivilege checks if the process is running with Administrator
// privileges (the Windows equivalent of root). If not, it exits the program.
func RequireRootPrivilege(cmd string) {
	if !hasAdminPrivilege() {
		fmt.Fprintf(os.Stderr, "Please run %q command(s) with Administrator privileges.\n", cmd)
		os.Exit(1)
	}
}

// hasAdminPrivilege reports whether the current process token is elevated or a
// member of the built-in Administrators group.
func hasAdminPrivilege() bool {
	token := windows.GetCurrentProcessToken()

	if token.IsElevated() {
		return true
	}

	adminSid, err := windows.CreateWellKnownSid(windows.WELL_KNOWN_SID_TYPE(windows.WinBuiltinAdministratorsSid))
	if err != nil {
		return false
	}

	member, err := token.IsMember(adminSid)
	if err != nil {
		return false
	}
	return member
}
