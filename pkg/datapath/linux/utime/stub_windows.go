// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package utime

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/time"
)

var Cell = cell.Module("utime", "Synchronizes utime offset between userspace and datapath")

type UTime uint64

func ToUTime(secs int64, nanos int) UTime {
	return UTime(secs)*1_000_000_000 + UTime(nanos)
}

func TimeToUTime(t time.Time) UTime {
	return ToUTime(t.Unix(), t.Nanosecond())
}

func (t UTime) Time() time.Time {
	secs := int64(t / 1_000_000_000)
	nanos := int64(t % 1_000_000_000)
	return time.Unix(secs, nanos)
}

func (t UTime) String() string { return t.Time().String() }
