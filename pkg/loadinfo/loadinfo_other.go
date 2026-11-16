// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package loadinfo

// LogCurrentSystemLoad is a no-op on non-Linux platforms. Gathering system load,
// memory statistics and per-process information relies on /proc and Linux-only
// libraries.
func LogCurrentSystemLoad(logFunc LogFunc) {
}
