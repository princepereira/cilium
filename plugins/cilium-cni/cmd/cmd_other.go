// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package cmd

import (
	"fmt"
	"os"
)

// Cmd is the CNI plugin implementation. On non-Linux platforms it carries no
// state as the veth/netlink-based datapath is unavailable.
type Cmd struct{}

// Option allows the customization of the Cmd implementation.
type Option func(cmd *Cmd)

// WithVersion overrides the version reported by the CNI plugin binary in its
// about string.
func WithVersion(version string) Option {
	return func(cmd *Cmd) {}
}

// PluginMain is the main entry point for the Cilium CNI plugin. It is not
// supported on non-Linux platforms.
func PluginMain(opts ...Option) {
	fmt.Fprintln(os.Stderr, "cilium-cni is not supported on this platform")
	os.Exit(1)
}
