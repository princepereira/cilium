// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package version

import (
	"errors"

	"github.com/blang/semver/v4"
)

// GetKernelVersion is not supported on Windows, which has no Linux kernel. It
// returns an error so that Linux-kernel-version gated code paths treat the
// feature as unavailable.
func GetKernelVersion() (semver.Version, error) {
	return semver.Version{}, errors.New("GetKernelVersion is not supported on Windows")
}
