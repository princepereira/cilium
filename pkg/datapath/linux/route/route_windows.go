// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package route

import (
	"fmt"
	"log/slog"

	"github.com/vishvananda/netlink"
)

var errUnsupportedOp = fmt.Errorf("Route operations not supported on Windows")

func Replace(route Route, mtuConfig any) error { return errUnsupportedOp }
func Delete(route Route) error                 { return errUnsupportedOp }
func NodeDeviceWithDefaultRoute(logger *slog.Logger, enableIPv4, enableIPv6 bool) (netlink.Link, error) {
	return nil, errUnsupportedOp
}
