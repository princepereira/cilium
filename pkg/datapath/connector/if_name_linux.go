// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package connector

import "golang.org/x/sys/unix"

const ifNameSize = unix.IFNAMSIZ
