// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package reflectors

import (
	"errors"
	"sync"

	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/netns"
)

func NetnsCookieSupportFunc() HaveNetNSCookieSupport {
	return sync.OnceValue(func() bool {
		_, err := netns.GetNetNSCookie()
		return !errors.Is(err, unix.ENOPROTOOPT)
	})
}
