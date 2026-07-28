// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package atomicfile provides atomic file replacement helpers with an API
// compatible with the subset of github.com/google/renameio/v2 that Cilium
// uses. On Linux it delegates to renameio so behavior is unchanged. On other
// platforms (e.g. Windows, where renameio does not export these helpers) it
// falls back to a portable temp-file + rename implementation.
package atomicfile

import "os"

// config holds the resolved options for an atomic write.
type config struct {
	perm        os.FileMode
	permSet     bool
	useExisting bool
}

// Option configures an atomic write operation.
type Option func(*config)

// WithPermissions sets the permission bits of the resulting file.
func WithPermissions(perm os.FileMode) Option {
	return func(c *config) {
		c.perm = perm & os.ModePerm
		c.permSet = true
	}
}

// WithExistingPermissions instructs the writer to reuse the permission bits of
// the file already present at the destination path (if any).
func WithExistingPermissions() Option {
	return func(c *config) {
		c.useExisting = true
	}
}

func newConfig(opts []Option) *config {
	c := &config{perm: 0o600}
	for _, o := range opts {
		o(c)
	}
	return c
}
