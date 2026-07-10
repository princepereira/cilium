// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package reflectors

// NetnsCookieSupportFunc reports whether the kernel supports network namespace
// cookies. This is a Linux-only socket feature (SO_NETNS_COOKIE); there is no
// Windows equivalent, so support is always reported as unavailable.
func NetnsCookieSupportFunc() HaveNetNSCookieSupport {
	return func() bool { return false }
}
