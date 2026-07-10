// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package reconciler

import "errors"

// errMapFull is the error returned by the datapath layer when a service or
// backend entry cannot be inserted because the underlying map is full. On
// Windows the datapath is CNC-backed rather than eBPF, so this is a sentinel
// that the CNC LB maps never return; it exists so that the platform-neutral
// reconciler code can reference it.
var errMapFull error = errors.New("load-balancer map full")
