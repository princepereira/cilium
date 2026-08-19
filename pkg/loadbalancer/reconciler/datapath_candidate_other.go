// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !windows

package reconciler

import "github.com/cilium/cilium/pkg/loadbalancer"

// platformDatapathCandidate is a no-op on non-Windows platforms: when
// KubeProxyReplacement is disabled, kube-proxy handles LoadBalancer and
// NodePort frontends, so Cilium must not program them into the datapath.
func platformDatapathCandidate(fe *loadbalancer.Frontend) bool {
	return false
}
