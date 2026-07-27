// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ebpf

import (
	ciliumebpf "github.com/cilium/ebpf"
)

type MapSpec = ciliumebpf.MapSpec

type PinType = ciliumebpf.PinType

const (
	Hash       = ciliumebpf.Hash
	PerCPUHash = ciliumebpf.PerCPUHash
	Array      = ciliumebpf.Array
	HashOfMaps = ciliumebpf.HashOfMaps
	LPMTrie    = ciliumebpf.LPMTrie
	LRUHash    = ciliumebpf.LRUHash
	LRUCPUHash = ciliumebpf.LRUCPUHash
	RingBuf    = ciliumebpf.RingBuf

	PinNone   = ciliumebpf.PinNone
	PinByName = ciliumebpf.PinByName
)

var (
	ErrKeyNotExist = ciliumebpf.ErrKeyNotExist
)

// IterateCallback represents the signature of the callback function expected by
// the IterateWithCallback method, which in turn is used to iterate all the
// keys/values of a map.
type IterateCallback func(key, value any)
