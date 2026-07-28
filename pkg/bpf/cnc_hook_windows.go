// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package bpf

import (
	"log/slog"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// MapOp identifies the kind of mutation that triggered a map sync hook.
type MapOp int

const (
	// MapOpUpdate is emitted after a successful in-memory Update.
	MapOpUpdate MapOp = iota
	// MapOpDelete is emitted after a successful in-memory Delete.
	MapOpDelete
)

// MapSyncHook mirrors a successful typed map mutation into an external
// datapath (on Windows, the CNC eBPF runtime behind cncapi.dll).
//
// Hooks receive the same typed MapKey/MapValue passed to Update/Delete, so the
// registering package can type-assert to its concrete key/value structs and
// translate them into semantic datapath calls. For deletes, value is nil.
type MapSyncHook func(op MapOp, key MapKey, value MapValue) error

var (
	mapHooksMu lock.RWMutex
	mapHooks   = map[string]MapSyncHook{}
)

// RegisterMapSyncHook registers a hook invoked after a successful in-memory
// Update/Delete on the named map. It is used to mirror Cilium's typed BPF map
// writes into the native Windows datapath. Registering a hook for a name that
// already has one replaces it.
func RegisterMapSyncHook(name string, hook MapSyncHook) {
	mapHooksMu.Lock()
	defer mapHooksMu.Unlock()
	mapHooks[name] = hook
}

// invokeMapSyncHook runs the hook registered for the given map name, if any.
// Errors are logged and swallowed: the in-memory map remains the source of
// truth, and a failure to mirror must not break the caller's map operation.
func invokeMapSyncHook(logger *slog.Logger, name string, op MapOp, key MapKey, value MapValue) {
	mapHooksMu.RLock()
	hook := mapHooks[name]
	mapHooksMu.RUnlock()
	if hook == nil {
		return
	}
	if err := hook(op, key, value); err != nil && logger != nil {
		logger.Warn("failed to mirror map write to CNC datapath",
			logfields.BPFMapName, name,
			logfields.Error, err,
		)
	}
}
