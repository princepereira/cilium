// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package reflectors

import "github.com/cilium/hive/cell"

// FileReflectorCell is a no-op on Windows.
var FileReflectorCell = cell.Module("file-reflector", "File reflector - no-op on Windows")

// Cell provides the Windows load-balancing reflectors.
var Cell = cell.Module(
	"loadbalancer-reflectors",
	"Reflects external state to load-balancing tables",
	K8sReflectorCell,
	FileReflectorCell,
	cell.Provide(NetnsCookieSupportFunc),
)

type HaveNetNSCookieSupport func() bool

func NetnsCookieSupportFunc() HaveNetNSCookieSupport {
	return func() bool { return false }
}
