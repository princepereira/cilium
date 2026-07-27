// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package proxy

// nodeEnsureLocalRoutingRule is a no-op on non-Linux platforms, where the
// Linux policy-routing rule used to steer proxy traffic does not apply.
func nodeEnsureLocalRoutingRule() error {
	return nil
}
