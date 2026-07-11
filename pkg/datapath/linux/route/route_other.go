// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package route

import (
	"fmt"
	"log/slog"
	"net"

	"github.com/vishvananda/netlink"
)

// MainTable is Linux's default routing table.
const MainTable = 254

// errUnsupportedOp is returned by all route operations on non-Linux platforms,
// where netlink route management is not available.
var errUnsupportedOp = fmt.Errorf("route operations are not supported on this platform")

// Rule is the non-Linux equivalent of the Linux routing rule specification. It
// mirrors the fields of the Linux implementation so that shared code compiles,
// but route operations are not supported at runtime.
type Rule struct {
	// Priority is the routing rule priority
	Priority int

	// Mark is the skb mark that needs to match
	Mark uint32

	// Mask is the mask to apply to the skb mark before matching the Mark field
	Mask uint32

	// From is the source address selector
	From *net.IPNet

	// To is the destination address selector
	To *net.IPNet

	// Table is the routing table to look up if the rule matches
	Table int

	// Protocol is the routing rule protocol (e.g. proto unspec/kernel)
	Protocol uint8
}

// Upsert is not supported on non-Linux platforms and returns an error at runtime.
func Upsert(logger *slog.Logger, route Route) error {
	return errUnsupportedOp
}

// Replace is not supported on non-Linux platforms and returns an error at runtime.
func Replace(route Route, mtuConfig any) error {
	return errUnsupportedOp
}

// Delete is not supported on non-Linux platforms and returns an error at runtime.
func Delete(route Route) error {
	return errUnsupportedOp
}

// ReplaceRule is not supported on non-Linux platforms and returns an error at runtime.
func ReplaceRule(spec Rule) error {
	return errUnsupportedOp
}

// ReplaceRuleIPv6 is not supported on non-Linux platforms and returns an error at runtime.
func ReplaceRuleIPv6(spec Rule) error {
	return errUnsupportedOp
}

// DeleteRule is not supported on non-Linux platforms and returns an error at runtime.
func DeleteRule(family int, spec Rule) error {
	return errUnsupportedOp
}

// DeleteRouteTable is not supported on non-Linux platforms and returns an error at runtime.
func DeleteRouteTable(table, family int) error {
	return errUnsupportedOp
}

// NodeDeviceWithDefaultRoute is not supported on non-Linux platforms and returns
// an error at runtime.
func NodeDeviceWithDefaultRoute(logger *slog.Logger, enableIPv4, enableIPv6 bool) (netlink.Link, error) {
	return nil, errUnsupportedOp
}
