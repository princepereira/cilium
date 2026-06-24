// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !windows

package policymap

import (
	"log/slog"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
	policyTypes "github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/u8proto"
)

type policyMap struct {
	*bpf.Map
	stats *StatsMap // shared stats map
	epID  uint16
}

// Update pushes an 'entry' into the PolicyMap for the given PolicyKey 'key'.
func (pm *policyMap) Update(key *PolicyKey, entry *PolicyEntry) error {
	if option.Config.Debug {
		pm.stats.ZeroStat(pm.epID, *key)
	}
	return pm.Map.Update(key, entry)
}

// DeleteKey deletes the key-value pair from the given PolicyMap with PolicyKey k.
func (pm *policyMap) DeleteKey(key PolicyKey) error {
	return pm.Map.Delete(&key)
}

// DeleteEntry removes an entry from the PolicyMap.
func (pm *policyMap) DeleteEntry(entry *PolicyEntryDump) error {
	return pm.Map.Delete(&entry.Key)
}

// String returns a human-readable string representing the policy map.
func (pm *policyMap) String() string {
	path, err := pm.Path()
	if err != nil {
		return err.Error()
	}
	return path
}

func (pm *policyMap) Dump() (string, error) {
	entries, err := pm.DumpToSlice()
	if err != nil {
		return "", err
	}
	return entries.String(), nil
}

func (pm *policyMap) DumpToSlice() (PolicyEntriesDump, error) {
	entries := PolicyEntriesDump{}

	cb := func(key bpf.MapKey, value bpf.MapValue) {
		eDump := PolicyEntryDump{
			Key:         *key.(*PolicyKey),
			PolicyEntry: *value.(*PolicyEntry),
		}
		entries = append(entries, eDump)
	}
	err := pm.DumpWithCallback(cb)
	if err != nil {
		return nil, err
	}

	// Fetch stats for all dumped entries
	if pm.stats != nil {
		for i := range entries {
			entries[i].Packets, entries[i].Bytes = pm.stats.GetStat(pm.epID, entries[i].Key)
		}
	}
	return entries, err
}

func (pm *policyMap) DumpToMapStateMap() (policyTypes.MapStateMap, error) {
	out := make(policyTypes.MapStateMap)

	cb := func(bpfKey bpf.MapKey, bpfVal bpf.MapValue) {
		key := bpfKey.(*PolicyKey)
		val := bpfVal.(*PolicyEntry)

		policyKey := policyTypes.KeyForDirection(trafficdirection.TrafficDirection(key.TrafficDirection)).
			WithIdentity(identity.NumericIdentity(key.Identity)).
			WithPortProtoPrefix(u8proto.U8proto(key.Nexthdr), key.GetDestPort(), key.GetPortPrefixLen())

		policyVal := policyTypes.MapStateEntry{
			Precedence:      val.Precedence,
			ProxyPort:       val.GetProxyPort(),
			AuthRequirement: val.AuthRequirement,
			Cookie:          val.Cookie,
		}.WithDeny(val.IsDeny())
		if !val.IsValid(key) {
			policyVal.Invalidate()
		}
		out[policyKey] = policyVal
	}
	err := pm.DumpWithCallback(cb)
	return out, err
}

func newPolicyMap(logger *slog.Logger, id uint16, maxEntries int, stats *StatsMap) (*policyMap, error) {
	path := bpf.LocalMapPath(logger, MapName, id)
	mapType := ebpf.LPMTrie
	flags := bpf.GetMapMemoryFlags(mapType)
	flags |= unix.BPF_F_RDONLY_PROG

	return &policyMap{
		Map: bpf.NewMap(
			path,
			mapType,
			&PolicyKey{},
			&PolicyEntry{},
			maxEntries,
			flags,
		).WithGroupName("endpoint_policy"),
		stats: stats,
		epID:  id,
	}, nil
}

// OpenPolicyMap opens the policymap at the specified path.
func OpenPolicyMap(logger *slog.Logger, path string) (*policyMap, error) {
	id, err := parseEndpointID(path)
	if err != nil {
		return nil, err
	}

	stats, err := OpenStatsMap(logger)
	if err != nil {
		return nil, err
	}

	m, err := bpf.OpenMap(path, &PolicyKey{}, &PolicyEntry{})
	if err != nil {
		return nil, err
	}

	return &policyMap{
		Map:   m,
		stats: stats,
		epID:  id,
	}, nil
}

// initCallMaps creates the policy call maps in the kernel.
func initCallMaps() error {
	policyCallMap := bpf.NewMap(PolicyCallMapName,
		ebpf.ProgramArray,
		&CallKey{},
		&CallValue{},
		int(PolicyCallMaxEntries),
		0,
	)
	if err := policyCallMap.Create(); err != nil {
		return err
	}

	policyEgressCallMap := bpf.NewMap(PolicyEgressCallMapName,
		ebpf.ProgramArray,
		&CallKey{},
		&CallValue{},
		int(PolicyCallMaxEntries),
		0,
	)
	return policyEgressCallMap.Create()
}