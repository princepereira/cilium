// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package health

// healthEndpointSupported reports whether the cilium-health node daemon and
// endpoint can be launched on this platform. Both rely on Linux network
// namespaces and veth devices.
const healthEndpointSupported = true
