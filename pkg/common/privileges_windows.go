// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package common

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// RequireRootPrivilege checks that cmd is running with Administrator privileges,
// the Windows equivalent of root. os.Getuid() is unimplemented on Windows (it
// always returns -1), so instead we check whether the process's effective token
// is a member of the built-in Administrators group. This is satisfied both when
// running elevated as an administrator and when running as NT AUTHORITY\SYSTEM
// (the common case for Windows HostProcess containers). If not, it exits.
func RequireRootPrivilege(cmd string) {
	if !isWindowsAdmin() {
		fmt.Fprintf(os.Stderr, "Please run %q command(s) with Administrator privileges.\n", cmd)
		os.Exit(1)
	}
}

func isWindowsAdmin() bool {
	var adminSID *windows.SID
	// S-1-5-32-544 = BUILTIN\Administrators
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&adminSID,
	)
	if err != nil {
		return false
	}
	defer windows.FreeSid(adminSID)

	// Passing the zero-value Token uses the current effective token
	// (CheckTokenMembership with a NULL token handle).
	member, err := windows.Token(0).IsMember(adminSID)
	return err == nil && member
}
