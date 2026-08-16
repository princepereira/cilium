// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package signalmap

import "github.com/cilium/ebpf/perf"

// Record is the signal record read from the perf event ring buffer. On Linux it
// is an alias of perf.Record.
type Record = perf.Record
