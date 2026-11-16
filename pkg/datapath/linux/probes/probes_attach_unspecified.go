// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package probes

// The following probes rely on Linux-only netlink/tc/tcx/netkit attach paths
// (see probes_attach_linux.go). On non-Linux platforms they report the feature
// as unsupported.

var HaveTCBPF = func() error { return ErrNotSupported }

var HaveTCX = func() error { return ErrNotSupported }

var HaveNetkit = func() error { return ErrNotSupported }

var HaveBIGTCPTunnel = func() error { return ErrNotSupported }

// HaveIPv6Support reports whether an IPv6 socket can be opened. It is defined
// here as unsupported for non-Linux builds.
func HaveIPv6Support() error { return ErrNotSupported }
