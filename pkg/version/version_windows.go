// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package version

import (
	"fmt"

	"github.com/blang/semver/v4"
)

// GetKernelVersion is not supported on Windows. The concept of a Linux kernel
// version does not apply, so it returns an error to make callers treat any
// kernel-version-gated feature as unavailable.
func GetKernelVersion() (semver.Version, error) {
	return semver.Version{}, fmt.Errorf("kernel version detection is not supported on Windows")
}
