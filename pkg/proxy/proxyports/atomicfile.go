// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package proxyports

import "io"

// pendingFile is an atomically-committed file handle. Writes go to a temporary
// file which is renamed into place on CloseAtomicallyReplace, or discarded on
// Cleanup.
type pendingFile interface {
	io.Writer
	Cleanup() error
	CloseAtomicallyReplace() error
}
