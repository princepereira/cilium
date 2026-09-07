// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package helpers

// pauseProcess is a no-op on non-Linux platforms. Pausing the test process via
// SIGSTOP for live debugging is only supported on Linux.
func pauseProcess(pid int) {}
