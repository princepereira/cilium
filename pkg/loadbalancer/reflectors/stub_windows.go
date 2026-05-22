// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package reflectors

import "github.com/cilium/hive/cell"

const K8sInitializerPrefix = "k8s-"

type K8sReflectorRegistered struct{}

var K8sReflectorCell = cell.Module("k8s-reflector", "Kubernetes reflector (unsupported on windows)", cell.Provide(func() K8sReflectorRegistered { return K8sReflectorRegistered{} }))
var FileReflectorCell = cell.Module("file-reflector", "File reflector (unsupported on windows)")
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
