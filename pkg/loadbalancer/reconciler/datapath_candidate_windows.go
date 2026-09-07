// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package reconciler

import "github.com/cilium/cilium/pkg/loadbalancer"

// platformDatapathCandidate reports whether a frontend type should additionally
// be programmed into the datapath maps on Windows when KubeProxyReplacement is
// disabled.
//
// Unlike Linux, a Windows node has no kube-proxy handling Service VIPs, so the
// eBPF-for-Windows datapath is the only thing that can translate LoadBalancer
// ingress/public IPs. We therefore program LoadBalancer frontends here as well
// (ClusterIP/ExternalIPs are already handled by the common path). NodePort
// frontends are still not reflected while KPR is off, so they never reach here.
func platformDatapathCandidate(fe *loadbalancer.Frontend) bool {
	return fe.Type == loadbalancer.SVCTypeLoadBalancer
}
