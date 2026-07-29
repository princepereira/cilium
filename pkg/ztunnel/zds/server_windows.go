// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package zds

// socketControlRights returns no control message on platforms that do not
// support passing file descriptors over Unix domain sockets (SCM_RIGHTS).
func socketControlRights(fd int) []byte {
	return nil
}
