// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package cmd

import "log/slog"

// verifyBPFTemplateDir is a no-op on non-Linux platforms. eBPF-for-Windows uses
// precompiled maps managed by the driver, so there are no C datapath templates
// or feature-macro header files to stat or generate.
func verifyBPFTemplateDir(scopedLog *slog.Logger) {}
