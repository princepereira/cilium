// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package envoy

// accessLogSocketNetwork is the AF_UNIX socket type used for the Envoy access
// log listener. On Linux a SEQPACKET socket is used to preserve message
// boundaries between Envoy and the agent.
const accessLogSocketNetwork = "unixpacket"
