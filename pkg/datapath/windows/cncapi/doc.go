// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

// Package cncapi provides the Windows datapath integration layer using cncshim.
// It implements domain-specific eBPF map operations on Windows via the CNC
// (Container Network Configuration) API, which communicates with the Windows
// kernel networking stack through cncapi.dll.
//
// This package acts as the bridge between Cilium's control plane (identity,
// load balancer, policy, endpoint, neighbor management) and the Windows
// networking datapath.
package cncapi
