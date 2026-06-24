// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package reconciler

import (
	"context"
	"fmt"
	"iter"
	"log/slog"
	"sort"
	"sync"
	"sync/atomic"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/loadbalancer/maps"
	"github.com/cilium/cilium/pkg/loadbalancer/writer"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/u8proto"
)

// SocketTerminationCell is a no-op on Windows.
var SocketTerminationCell = cell.Module(
	"loadbalancer-socket-termination",
	"Socket termination - no-op on Windows",
)

// Cell provides the Windows CNC-based LB reconciler.
var Cell = cell.Module(
	"loadbalancer-reconciler",
	"Load-balancing CNC reconciliation for Windows",

	cell.Provide(newCNCOps),

	cell.ProvidePrivate(newCNCReconciler),

	cell.Invoke(
		func(promise.Promise[reconciler.Reconciler[*loadbalancer.Frontend]]) {},
	),
)

// CNCOps implements reconciler.Operations[*loadbalancer.Frontend] for Windows.
// It translates Frontend table changes into LBMaps calls, which CNCLBMaps
// then forwards to the CNC API.
type CNCOps struct {
	mu  sync.Mutex
	log *slog.Logger

	LBMaps maps.LBMaps

	// backends table for direct diagnostic queries
	backends statedb.Table[*loadbalancer.Backend]

	// serviceIDAlloc and backendIDAlloc assign stable numeric IDs.
	serviceIDAlloc idAllocator[loadbalancer.ServiceID]
	backendIDAlloc idAllocator[loadbalancer.BackendID]

	// backendReferences tracks the number of backends last reconciled per frontend.
	backendReferences map[loadbalancer.L3n4Addr]int

	lastUpdatedAt atomic.Pointer[time.Time]
}

type cncOpsParams struct {
	cell.In

	Log      *slog.Logger
	LBMaps   maps.LBMaps
	Backends statedb.Table[*loadbalancer.Backend]
}

func newCNCOps(p cncOpsParams) *CNCOps {
	return &CNCOps{
		log:               p.Log,
		LBMaps:            p.LBMaps,
		backends:          p.Backends,
		serviceIDAlloc:    newIDAllocator[loadbalancer.ServiceID](firstFreeServiceID, maxSetOfServiceID),
		backendIDAlloc:    newIDAllocator[loadbalancer.BackendID](firstFreeBackendID, maxSetOfBackendID),
		backendReferences: make(map[loadbalancer.L3n4Addr]int),
	}
}

func newCNCReconciler(
	p reconciler.Params,
	jobs job.Registry,
	health cell.Health,
	g job.Group,
	cfg loadbalancer.Config,
	ops *CNCOps,
	fes statedb.Table[*loadbalancer.Frontend],
	w *writer.Writer,
) promise.Promise[reconciler.Reconciler[*loadbalancer.Frontend]] {
	resolve, prom := promise.New[reconciler.Reconciler[*loadbalancer.Frontend]]()
	if !w.IsEnabled() {
		resolve.Resolve(nil)
	}
	g.Add(
		job.OneShot("start-reconciler", func(ctx context.Context, health cell.Health) error {
			p.Log.Info("CNC reconciler: waiting for LB tables to initialize")
			health.OK("Waiting for load-balancing tables to initialize")
			_, initWatch := w.Frontends().Initialized(p.DB.ReadTxn())
			select {
			case <-ctx.Done():
				return nil
			case <-initWatch:
				p.Log.Info("CNC reconciler: tables initialized, registering reconciler")
			case <-time.After(cfg.InitWaitTimeout):
				p.Log.Warn("Timed out waiting for load-balancing state to initialize")
			}

			r, err := reconciler.Register(
				p,
				fes.(statedb.RWTable[*loadbalancer.Frontend]),

				(*loadbalancer.Frontend).Clone,
				func(fe *loadbalancer.Frontend, s reconciler.Status) *loadbalancer.Frontend {
					fe.Status = s
					return fe
				},
				func(fe *loadbalancer.Frontend) reconciler.Status {
					return fe.Status
				},
				ops,
				nil, // no batching

				reconciler.WithRetry(
					cfg.RetryBackoffMin,
					cfg.RetryBackoffMax,
				),

				reconciler.WithPruning(
					30*time.Minute,
				),
			)
			if err == nil {
				p.Log.Info("CNC reconciler: registered successfully")
				resolve.Resolve(r)
			} else {
				p.Log.Error("CNC reconciler: registration failed", "error", err)
				resolve.Reject(err)
			}
			return err
		}),
	)
	return prom
}

// Update reconciles a Frontend change by programming backends and service
// entries into the LBMaps (which CNCLBMaps translates to CNC API calls).
func (ops *CNCOps) Update(_ context.Context, txn statedb.ReadTxn, _ statedb.Revision, fe *loadbalancer.Frontend) error {
	ops.mu.Lock()
	defer ops.mu.Unlock()
	ops.setLastUpdatedAt()

	ops.log.Info("CNCOps.Update called", "frontend", fe.Address.String(), "service", fe.ServiceName.String())

	// Diagnostic: directly query Backend table to see if backends exist for this service
	directBEs, _ := loadbalancer.ListBackendsByServiceName(txn, ops.backends, fe.ServiceName)
	directCount := 0
	for range directBEs {
		directCount++
	}
	ops.log.Info("CNCOps.Update diagnostics",
		"frontend", fe.Address.String(),
		"service", fe.ServiceName.String(),
		"directBackendCount", directCount,
		"feBackendsNil", fe.Backends == nil,
	)

	// Assign/lookup service ID
	feID, err := ops.serviceIDAlloc.acquireLocalID(fe.Address)
	if err != nil {
		return fmt.Errorf("failed to allocate service id: %w", err)
	}
	fe.ID = loadbalancer.ServiceID(feID)

	proto, err := u8proto.ParseProtocol(fe.Address.Protocol())
	if err != nil {
		return fmt.Errorf("invalid L4 protocol %q: %w", fe.Address.Protocol(), err)
	}

	var svcKey maps.ServiceKey
	var svcVal maps.ServiceValue

	ip := fe.Address.AddrCluster().AsNetIP()
	if fe.Address.IsIPv6() {
		svcKey = maps.NewService6Key(ip, fe.Address.Port(), proto, fe.Address.Scope(), 0)
		svcVal = &maps.Service6Value{}
	} else {
		svcKey = maps.NewService4Key(ip, fe.Address.Port(), proto, fe.Address.Scope(), 0)
		svcVal = &maps.Service4Value{}
	}

	// Gather and sort backends from the Frontend
	orderedBackends := ops.sortedBackends(fe)

	// Upsert each backend and write service slot entries
	slotID := 1
	activeCount := 0

	for _, be := range orderedBackends {
		if be.State == loadbalancer.BackendStateMaintenance {
			continue
		}

		// Allocate/lookup backend ID
		beID, err := ops.backendIDAlloc.acquireLocalID(be.Address)
		if err != nil {
			ops.log.Error("failed to allocate backend id", "backend", be.Address.String(), "error", err)
			return fmt.Errorf("failed to allocate backend id: %w", err)
		}

		// Upsert backend into maps
		if err := ops.upsertBackend(beID, be); err != nil {
			ops.log.Error("upsertBackend failed", "backendID", beID, "backend", be.Address.String(), "error", err)
			return fmt.Errorf("upsert backend: %w", err)
		}

		// Write service slot entry (slot > 0)
		svcVal.SetBackendID(beID)
		svcVal.SetRevNat(int(feID))
		svcKey.SetBackendSlot(slotID)
		if err := ops.LBMaps.UpdateService(svcKey.ToNetwork(), svcVal.ToNetwork()); err != nil {
			ops.log.Error("UpdateService slot failed", "slot", slotID, "frontend", fe.Address.String(), "error", err)
			return fmt.Errorf("upsert service slot: %w", err)
		}

		activeCount++
		slotID++
	}

	// Write master entry (slot 0) — this triggers CNC service creation + backend association
	svcVal.SetCount(activeCount)
	svcVal.SetBackendID(0)
	svcVal.SetRevNat(int(feID))
	svcKey.SetBackendSlot(0)

	svcType := fe.Type
	flag := loadbalancer.NewSvcFlag(&loadbalancer.SvcFlagParam{
		SvcType: svcType,
	})
	svcVal.SetFlags(flag.UInt16())

	if err := ops.LBMaps.UpdateService(svcKey.ToNetwork(), svcVal.ToNetwork()); err != nil {
		ops.log.Warn("CNCOps.Update failed at master slot", "frontend", fe.Address.String(), "error", err)
		return fmt.Errorf("upsert service master: %w", err)
	}

	// Cleanup old slots if count decreased
	prevCount := ops.backendReferences[fe.Address]
	if prevCount > activeCount {
		for i := activeCount + 1; i <= prevCount; i++ {
			svcKey.SetBackendSlot(i)
			_ = ops.LBMaps.DeleteService(svcKey.ToNetwork())
		}
	}
	ops.backendReferences[fe.Address] = activeCount

	ops.log.Info("Frontend reconciled",
		logfields.Address, fe.Address,
		"service", fe.ServiceName.String(),
		"backends", activeCount,
	)

	return nil
}

// Delete removes a frontend and its associated entries from CNC.
func (ops *CNCOps) Delete(_ context.Context, txn statedb.ReadTxn, _ statedb.Revision, fe *loadbalancer.Frontend) error {
	ops.mu.Lock()
	defer ops.mu.Unlock()
	ops.setLastUpdatedAt()

	proto, err := u8proto.ParseProtocol(fe.Address.Protocol())
	if err != nil {
		return nil
	}

	var svcKey maps.ServiceKey
	ip := fe.Address.AddrCluster().AsNetIP()
	if fe.Address.IsIPv6() {
		svcKey = maps.NewService6Key(ip, fe.Address.Port(), proto, fe.Address.Scope(), 0)
	} else {
		svcKey = maps.NewService4Key(ip, fe.Address.Port(), proto, fe.Address.Scope(), 0)
	}

	// Delete all slot entries
	prevCount := ops.backendReferences[fe.Address]
	for i := 1; i <= prevCount; i++ {
		svcKey.SetBackendSlot(i)
		_ = ops.LBMaps.DeleteService(svcKey.ToNetwork())
	}

	// Delete master entry (slot 0) — triggers CNC DeleteLoadBalancerService
	svcKey.SetBackendSlot(0)
	if err := ops.LBMaps.DeleteService(svcKey.ToNetwork()); err != nil {
		return fmt.Errorf("delete service: %w", err)
	}

	// Release service ID
	feID, _ := ops.serviceIDAlloc.lookupLocalID(fe.Address)
	ops.serviceIDAlloc.deleteLocalID(feID)
	delete(ops.backendReferences, fe.Address)

	return nil
}

// Prune removes stale entries that are not in the desired state.
func (ops *CNCOps) Prune(_ context.Context, txn statedb.ReadTxn, fes iter.Seq2[*loadbalancer.Frontend, statedb.Revision]) error {
	// On Windows, pruning is handled by tracking state in CNCLBMaps.
	return nil
}

// sortedBackends gathers and sorts backends from the frontend.
func (ops *CNCOps) sortedBackends(fe *loadbalancer.Frontend) []*loadbalancer.Backend {
	var backends []*loadbalancer.Backend
	if fe.Backends == nil {
		ops.log.Warn("sortedBackends: fe.Backends is nil", "frontend", fe.Address.String())
		return nil
	}
	for be := range fe.Backends {
		ops.log.Info("sortedBackends: yielded backend", "frontend", fe.Address.String(), "backend", be.Address.String(), "state", be.State)
		backends = append(backends, be)
	}
	ops.log.Info("sortedBackends result", "frontend", fe.Address.String(), "count", len(backends))

	// Sort: active first, then by address for stability
	sort.Slice(backends, func(i, j int) bool {
		if backends[i].State != backends[j].State {
			return backends[i].State < backends[j].State
		}
		return backends[i].Address.StringWithProtocol() < backends[j].Address.StringWithProtocol()
	})
	return backends
}

func (ops *CNCOps) upsertBackend(id loadbalancer.BackendID, be *loadbalancer.Backend) error {
	proto, err := u8proto.ParseProtocol(be.Address.Protocol())
	if err != nil {
		return fmt.Errorf("invalid L4 protocol %q: %w", be.Address.Protocol(), err)
	}

	var lbbe maps.Backend
	if be.Address.AddrCluster().Is6() {
		lbbe, err = maps.NewBackend6V3(id, be.Address.AddrCluster(), be.Address.Port(), proto,
			be.State, 0)
	} else {
		lbbe, err = maps.NewBackend4V3(id, be.Address.AddrCluster(), be.Address.Port(), proto,
			be.State, 0)
	}
	if err != nil {
		return err
	}
	return ops.LBMaps.UpdateBackend(lbbe.GetKey(), lbbe.GetValue().ToNetwork())
}

func (ops *CNCOps) setLastUpdatedAt() {
	t := time.Now()
	ops.lastUpdatedAt.Store(&t)
}
