// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package version

import (
	"errors"

	"github.com/blang/semver/v4"
)

// GetKernelVersion returns the version of the kernel running on this host. The
// Linux kernel version is not meaningful on Windows, so this returns an error.
func GetKernelVersion() (semver.Version, error) {
	return semver.Version{}, errors.New("kernel version is not available on this platform")
}
