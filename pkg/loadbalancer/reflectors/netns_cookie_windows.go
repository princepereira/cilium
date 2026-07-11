// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package reflectors

// NetnsCookieSupportFunc returns a probe that always reports no netns cookie
// support, as network namespace cookies are a Linux-specific concept.
func NetnsCookieSupportFunc() HaveNetNSCookieSupport {
	return func() bool {
		return false
	}
}