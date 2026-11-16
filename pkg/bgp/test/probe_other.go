// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package test

// TCPMD5SigAvailable reports whether the TCP_MD5SIG socket option can be set.
// It is always unavailable on non-Linux platforms.
func TCPMD5SigAvailable() (bool, error) {
	return false, nil
}
