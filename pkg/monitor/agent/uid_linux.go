// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package agent

import "os"

func runningAsRoot() bool {
	return os.Getuid() == 0
}
