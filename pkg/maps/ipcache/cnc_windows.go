// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package ipcache

import (
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/cnc"
)

// init wires the ipcache BPF map into the native Windows CNC datapath. Every
// successful in-memory Update/Delete on cilium_ipcache_v2 is mirrored to
// cncapi as a SetIdentity/DeleteIdentity call (CIDR -> security identity).
func init() {
	bpf.RegisterMapSyncHook(Name, ipcacheCNCHook)
}

func ipcacheCNCHook(op bpf.MapOp, key bpf.MapKey, value bpf.MapValue) error {
	k, ok := key.(*Key)
	if !ok {
		return nil
	}
	prefix := k.Prefix()
	if !prefix.IsValid() {
		return nil
	}

	switch op {
	case bpf.MapOpUpdate:
		v, ok := value.(*RemoteEndpointInfo)
		if !ok {
			return nil
		}
		return cnc.SetIdentity(prefix, v.SecurityIdentity)
	case bpf.MapOpDelete:
		return cnc.DeleteIdentity(prefix)
	}
	return nil
}
