// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package fake

import "golang.org/x/sys/unix"

const rtScopeUniverse = unix.RT_SCOPE_UNIVERSE
