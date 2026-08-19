// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package iptables

// iptablesSupported reports whether the iptables/ip6tables binaries and the
// underlying netfilter subsystem are available on this platform. Non-Linux
// platforms (e.g. Windows) have no iptables/netfilter, so the iptables
// datapath is disabled and all rule programming becomes a no-op.
const iptablesSupported = false
