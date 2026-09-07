// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package linux_defaults

import "golang.org/x/sys/unix"

// RTProto is the protocol we install our fib rules and routes with. Use the
// kernel proto to make sure systemd-networkd doesn't interfere with these rules
// (see networkd config directive ManageForeignRoutingPolicyRules, set to 'yes'
// by default).
const RTProto = unix.RTPROT_KERNEL
