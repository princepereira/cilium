// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package route

import (
	"fmt"
	"log/slog"
	"net"

	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/time"
)

// The route package manipulates the Linux routing tables and policy routing
// rules through netlink. None of that exists on Windows, so the operations
// below are stubs that return an error at runtime. The exported types and
// constants are kept identical to the Linux implementation so that
// cross-platform callers continue to compile.

const (
	// RouteReplaceMaxTries is the number of attempts the route will be
	// attempted to be added or updated in case the kernel returns an error.
	RouteReplaceMaxTries = 10

	// RouteReplaceRetryInterval is the interval in which
	// RouteReplaceMaxTries attempts are attempted.
	RouteReplaceRetryInterval = 100 * time.Millisecond

	// RTN_LOCAL is a route type used to indicate packet should be "routed"
	// locally and passed up the stack.
	RTN_LOCAL = 0x2

	// MainTable is Linux's default routing table.
	MainTable = 254

	// EncryptRouteProtocol for Encryption specific routes.
	EncryptRouteProtocol = 192
)

// errUnsupported is returned by all route operations on Windows.
var errUnsupported = fmt.Errorf("route operations are not supported on Windows")

// Rule is a policy routing rule. It mirrors the Linux definition so that
// callers can build rules on any platform.
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

// String returns the string representation of a Rule.
func (r Rule) String() string {
	from := "all"
	if r.From != nil {
		from = r.From.String()
	}
	to := "all"
	if r.To != nil {
		to = r.To.String()
	}
	str := fmt.Sprintf("%d: from %s to %s lookup %d", r.Priority, from, to, r.Table)
	if r.Mark != 0 {
		str += fmt.Sprintf(" mark 0x%x mask 0x%x", r.Mark, r.Mask)
	}
	return str
}

// Lookup is not supported on Windows.
func Lookup(route Route) (*Route, error) {
	return nil, errUnsupported
}

// Upsert is not supported on Windows.
func Upsert(logger *slog.Logger, route Route) error {
	return errUnsupported
}

// Delete is not supported on Windows.
func Delete(route Route) error {
	return errUnsupported
}

// ReplaceRule is not supported on Windows.
func ReplaceRule(spec Rule) error {
	return errUnsupported
}

// ReplaceRuleIPv6 is not supported on Windows.
func ReplaceRuleIPv6(spec Rule) error {
	return errUnsupported
}

// DeleteRule is not supported on Windows.
func DeleteRule(family int, spec Rule) error {
	return errUnsupported
}

// ListRules is not supported on Windows.
func ListRules(family int, filter *Rule) ([]netlink.Rule, error) {
	return nil, errUnsupported
}

// DeleteRouteTable is not supported on Windows.
func DeleteRouteTable(table, family int) error {
	return errUnsupported
}

// NodeDeviceWithDefaultRoute is not supported on Windows.
func NodeDeviceWithDefaultRoute(logger *slog.Logger, enableIPv4, enableIPv6 bool) (netlink.Link, error) {
	return nil, errUnsupported
}
