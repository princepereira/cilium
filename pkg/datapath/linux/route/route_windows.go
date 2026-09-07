// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package route

import (
	"fmt"
	"log/slog"

	"github.com/vishvananda/netlink"
)

// errUnsupportedOp is a common error returned by the Windows stub
// implementations of the route operations.
var errUnsupportedOp = fmt.Errorf("route operations not supported on Windows")

// Delete is not supported on Windows and will return an error at runtime.
func Delete(route Route) error {
	return errUnsupportedOp
}

// NodeDeviceWithDefaultRoute is not supported on Windows and will return
// an error at runtime.
func NodeDeviceWithDefaultRoute(logger *slog.Logger, enableIPv4, enableIPv6 bool) (netlink.Link, error) {
	return nil, errUnsupportedOp
}
