// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package probes

// HaveAttachCgroup relies on the Linux-only cgroup BPF attach path (see
// attach_cgroup_linux.go). On non-Linux platforms it reports the feature as
// unsupported.
var HaveAttachCgroup = func() error { return ErrNotSupported }
