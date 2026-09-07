// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package stats

// Stats report command-line flag names. These are cross-platform so that
// command wiring (e.g. cilium-dbg) can reference them on all platforms even
// though the report implementation itself is Linux-only.
const (
	SortFlagName   = "sort"
	PodFlagName    = "pod"
	DeviceFlagName = "device"
	JSONFlag       = "json"
)
