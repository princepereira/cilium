// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package agent

import "context"

// perfReader is a stub for platforms where the perf event ring buffer reader is
// not available. It is only referenced as a pointer field on the agent.
type perfReader struct{}

// handleEvents is a no-op on non-Linux platforms. Reading events from the BPF
// perf ring buffer relies on the Linux-only perf reader.
func (a *agent) handleEvents(stopCtx context.Context) {
	<-stopCtx.Done()
}
