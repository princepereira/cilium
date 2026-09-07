// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package linux_defaults

// RTProto is the protocol we install our fib rules and routes with. On non-Linux
// platforms there is no rtnetlink; the value mirrors Linux's RTPROT_KERNEL (2)
// so that constants referencing it retain a stable, portable definition.
const RTProto = 2
