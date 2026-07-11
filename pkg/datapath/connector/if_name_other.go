// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package connector

// Linux IFNAMSIZ is used for Cilium-generated endpoint interface names.
const ifNameSize = 16
