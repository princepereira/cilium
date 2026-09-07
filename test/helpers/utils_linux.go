// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package helpers

import "golang.org/x/sys/unix"

// pauseProcess stops the given process by sending SIGSTOP so a developer can
// attach and debug the live environment. Resumed via "kill -SIGCONT".
func pauseProcess(pid int) {
	unix.Kill(pid, unix.SIGSTOP)
}
