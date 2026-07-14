// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package common

import "golang.org/x/sys/windows"

// hasRootPrivilege reports whether the current process is running with
// Administrator privileges, which is the Windows equivalent of running as root.
// os.Getuid always returns -1 on Windows, so we instead check whether the
// process token is a member of the built-in Administrators group.
func hasRootPrivilege() bool {
	var sid *windows.SID
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid,
	)
	if err != nil {
		return false
	}
	defer windows.FreeSid(sid)

	// Passing a zero-value token refers to the current process token.
	token := windows.Token(0)
	member, err := token.IsMember(sid)
	if err != nil {
		return false
	}
	return member
}
