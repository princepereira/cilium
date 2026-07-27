// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package reflectors

// Network namespace cookies are a Linux-only concept, so support is always
// reported as unavailable on other platforms.
func NetnsCookieSupportFunc() HaveNetNSCookieSupport {
	return func() bool { return false }
}
