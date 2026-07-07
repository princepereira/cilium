// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package reconciler

import "golang.org/x/sys/unix"

// errMapFull is the error returned by the BPF map layer when a service or
// backend entry cannot be inserted because the underlying map is full. On Linux
// this maps to the E2BIG errno returned by the kernel.
var errMapFull error = unix.E2BIG
