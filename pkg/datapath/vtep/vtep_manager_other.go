// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package vtep

// setupRouteToVTEPCidr programs VTEP routes and rules via the Linux routing
// subsystem, which has no portable equivalent. It is a no-op on non-Linux
// platforms.
func (r *vtepManager) setupRouteToVTEPCidr() error {
	return nil
}
