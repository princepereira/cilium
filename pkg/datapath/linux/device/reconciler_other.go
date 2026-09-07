// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package device

import (
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/pkg/option"
)

// registerReconciler is a no-op on non-Linux platforms. The device reconciler
// programs interfaces via the Linux netlink handle, which has no portable
// equivalent, so no reconciler is registered.
func registerReconciler(
	params reconciler.Params,
	lc cell.Lifecycle,
	tbl statedb.RWTable[*DesiredDevice],
	log *slog.Logger,
	config *option.DaemonConfig,
) (reconciler.Reconciler[*DesiredDevice], error) {
	return nil, nil
}
