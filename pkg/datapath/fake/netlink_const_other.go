// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package fake

// rtScopeUniverse mirrors unix.RT_SCOPE_UNIVERSE (0) on non-Linux platforms.
const rtScopeUniverse = 0
