// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import "io"

// atomicFile is an atomically-replaced temporary file. Data written to it is
// only moved to the final destination when CloseAtomicallyReplace succeeds.
type atomicFile interface {
	io.Writer
	// Cleanup removes the temporary file if it has not been committed.
	Cleanup() error
	// CloseAtomicallyReplace atomically replaces the destination file with the
	// temporary file's contents.
	CloseAtomicallyReplace() error
}
