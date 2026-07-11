// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package utime

import (
	"fmt"

	"github.com/cilium/cilium/pkg/time"
)

func getBoottime() (time.Time, error) {
	return time.Time{}, fmt.Errorf("utime boot time is not supported on this platform")
}
