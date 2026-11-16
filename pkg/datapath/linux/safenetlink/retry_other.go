// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package safenetlink

// WithRetry runs netlinkFunc once. The dump-interrupt retry semantics only
// exist for the Linux netlink socket (netlink.ErrDumpInterrupted is Linux-only),
// so on other platforms this is a straight pass-through.
func WithRetry(netlinkFunc func() error) error {
	return netlinkFunc()
}

// WithRetryResult works like WithRetry, but allows netlinkFunc to have a return
// value besides the error.
func WithRetryResult[T any](netlinkFunc func() (T, error)) (out T, err error) {
	return netlinkFunc()
}
