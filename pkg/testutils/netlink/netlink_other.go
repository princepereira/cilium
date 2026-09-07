// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

// Package netlink provides netlink-based test helpers. The implementation is
// Linux-only; this file keeps the package non-empty on other platforms where
// it has no consumers.
package netlink
