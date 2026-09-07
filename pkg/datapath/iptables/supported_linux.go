// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package iptables

// iptablesSupported reports whether the iptables/ip6tables binaries and the
// underlying netfilter subsystem are available on this platform. On Linux the
// iptables datapath is fully supported.
const iptablesSupported = true
