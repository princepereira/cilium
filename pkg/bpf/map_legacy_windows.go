// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package bpf

import (
	"github.com/cilium/ebpf"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

// legacyMapAliases maps a map's canonical (current) pinned name to the older
// names an already-loaded eBPF-for-Windows datapath may have pinned it under.
// Cilium renamed several maps by appending a version suffix (…_v2 / …_v3); a
// datapath compiled before the rename pins the map under its original name.
// winebpfmap handles this same version skew by preferring the datapath's own
// pinned name and falling back to the legacy name, so the control plane and
// datapath resolve to the same pinned object instead of two unshared maps.
//
// Only maps whose key/value geometry is identical across the rename are listed
// here: reusing a pin whose value size differs would make eBPF-go treat the
// datapath's map as incompatible and unpin/recreate it, breaking the datapath.
// (For example the v1 cilium_ipcache and v2 cilium_ipcache_v2 have different
// value widths, so ipcache is deliberately NOT aliased.)
var legacyMapAliases = map[string][]string{
	"cilium_lb4_services_v2": {"cilium_lb4_services"},
	"cilium_lb6_services_v2": {"cilium_lb6_services"},
	"cilium_lb4_backends_v3": {"cilium_lb4_backends_v2", "cilium_lb4_backends"},
	"cilium_lb6_backends_v3": {"cilium_lb6_backends_v2", "cilium_lb6_backends"},
}

// pinExists reports whether an eBPF map is currently pinned at pinPath.
func pinExists(pinPath string) bool {
	m, err := ebpf.LoadPinnedMap(pinPath, nil)
	if err != nil {
		return false
	}
	m.Close()
	return true
}

// applyLegacyMapAlias rewrites the map's pin name/path to a legacy name when the
// currently-loaded datapath pinned the map under that older name. Cilium renamed
// several maps by appending a version suffix (…_v2 / …_v3); an eBPF-for-Windows
// datapath compiled before the rename pins (and its programs bind to) the map
// under its original name.
//
// The agent itself only ever creates the canonical (suffixed) name, so any pin
// found under a legacy name must belong to the datapath. We therefore PREFER an
// existing legacy pin over the canonical one — otherwise a stale v2/v3 map the
// agent created on an earlier run would shadow the datapath's real map and the
// two sides would never share an object. This mirrors winebpfmap, which prefers
// the datapath's own pinned map name and only falls back to the canonical name
// when no legacy pin exists.
func (m *Map) applyLegacyMapAlias() {
	aliases, ok := legacyMapAliases[m.name]
	if !ok {
		return
	}

	for _, legacy := range aliases {
		legacyPath := MapPath(m.Logger, legacy)
		if !pinExists(legacyPath) {
			continue
		}

		m.Logger.Info(
			"Reusing datapath's legacy-named BPF map pin",
			logfields.BPFMapName, m.name,
			logfields.BPFMapPath, legacyPath,
		)
		m.name = legacy
		m.path = legacyPath
		if m.spec != nil {
			m.spec.Name = legacy
		}
		return
	}
}
