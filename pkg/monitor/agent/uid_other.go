// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package agent

func runningAsRoot() bool {
	return false
}
