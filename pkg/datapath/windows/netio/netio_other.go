// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !windows

// Package netio provides cgo-free bindings for the Windows netioapi / iphlpapi
// surface used by the Cilium datapath on Windows. The implementation lives in
// the windows-tagged files; this file only exists so the package remains
// buildable (as an empty package) on non-Windows platforms, keeping
// `go build ./...` green everywhere.
package netio
