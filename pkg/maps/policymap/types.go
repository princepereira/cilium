// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policymap

import (
	"fmt"
	"strconv"
	"strings"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
	policyTypes "github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/u8proto"
)

const (
	// PolicyCallMapName is the name of the map to do tail calls into policy
	// enforcement programs.
	PolicyCallMapName = "cilium_call_policy"

	// PolicyEgressCallMapName is the name of the map to do tail calls into egress policy
	// enforcement programs.
	PolicyEgressCallMapName = "cilium_egresscall_policy"

	// MapName is the prefix for endpoint-specific policy maps which map
	// identity+ports+direction to whether the policy allows communication
	// with that identity on that port for that direction.
	MapName = "cilium_policy_v2_"

	// PolicyCallMaxEntries is the upper limit of entries in the program
	// array for the tail calls to jump into the endpoint specific policy
	// programs. This number *MUST* be identical to the maximum endpoint ID.
	PolicyCallMaxEntries = ^uint16(0)

	// AllPorts is used to ignore the L4 ports in PolicyMap lookups; all ports
	// are allowed. In the datapath, this is represented with the value 0 in the
	// port field of map elements.
	AllPorts = uint16(0)

	// SinglePortPrefixLen represents the mask argument required to lookup or
	// insert a single port key into the bpf map.
	SinglePortPrefixLen = uint8(16)
)

// policyEntryFlags is a new type used to define the flags used in the policy entry.
type policyEntryFlags uint8

const (
	policyFlagDeny policyEntryFlags = 1 << iota
	policyFlagReserved1
	policyFlagReserved2
	policyFlagLPMShift         = iota
	policyFlagMaskLPMPrefixLen = ((1 << 5) - 1) << policyFlagLPMShift
)

func (pef policyEntryFlags) is(pf policyEntryFlags) bool {
	return pef&pf == pf
}

func (pef policyEntryFlags) getPrefixLen() uint8 {
	return uint8(pef >> policyFlagLPMShift)
}

// String returns the string implementation of policyEntryFlags.
func (pef policyEntryFlags) String() string {
	var str []string
	if pef.is(policyFlagDeny) {
		str = append(str, "Deny")
	} else {
		str = append(str, "Allow")
	}
	return strings.Join(str, ", ")
}

// PolicyMap is the interface implemented by both Linux BPF and Windows CNC policy maps.
type PolicyMap interface {
	Update(key *PolicyKey, entry *PolicyEntry) error
	DeleteKey(key PolicyKey) error
	DeleteEntry(entry *PolicyEntryDump) error
	String() string
	Dump() (string, error)
	DumpToSlice() (PolicyEntriesDump, error)
	DumpToMapStateMap() (policyTypes.MapStateMap, error)

	MaxEntries() uint32
	Close() error
}

// PolicyKey represents a key in the BPF policy map for an endpoint.
//
// Must be in sync with struct policy_key in <bpf/lib/policy.h>
type PolicyKey struct {
	Prefixlen        uint32 `align:"lpm_key"`
	Identity         uint32 `align:"sec_label"`
	TrafficDirection uint8  `align:"egress"`
	Nexthdr          uint8  `align:"protocol"`
	DestPortNetwork  uint16 `align:"dport"` // In network byte-order
}

// GetDestPort returns the DestPortNetwork in host byte order
func (k *PolicyKey) GetDestPort() uint16 {
	return byteorder.NetworkToHost16(k.DestPortNetwork)
}

// GetPortMask returns the port mask of the key
func (k *PolicyKey) GetPortMask() uint16 {
	return 0xffff << (16 - k.GetPortPrefixLen())
}

// GetPortPrefixLen returns the prefix length applicable to the port in the key
func (k *PolicyKey) GetPortPrefixLen() uint8 {
	prefixLen := k.GetPrefixLen()
	if prefixLen <= NexthdrBits {
		return 0
	}
	return prefixLen - NexthdrBits
}

// GetPrefixLen returns the prefix length applicable to the protocol and port in the key
func (k *PolicyKey) GetPrefixLen() uint8 {
	return uint8(k.Prefixlen - StaticPrefixBits)
}

const (
	sizeofPolicyKey = int(unsafe.Sizeof(PolicyKey{}))
	sizeofPrefixlen = int(unsafe.Sizeof(PolicyKey{}.Prefixlen))
	sizeofNexthdr   = int(unsafe.Sizeof(PolicyKey{}.Nexthdr))
	sizeofDestPort  = int(unsafe.Sizeof(PolicyKey{}.DestPortNetwork))

	NexthdrBits    = uint8(sizeofNexthdr) * 8
	DestPortBits   = uint8(sizeofDestPort) * 8
	FullPrefixBits = NexthdrBits + DestPortBits

	StaticPrefixBits = uint32(sizeofPolicyKey-sizeofPrefixlen)*8 - uint32(FullPrefixBits)
)

// PolicyEntry represents an entry in the BPF policy map for an endpoint.
//
// Must be in sync with struct policy_entry in <bpf/lib/policy.h>
type PolicyEntry struct {
	ProxyPortNetwork uint16                      `align:"proxy_port"` // In network byte-order
	Flags            policyEntryFlags            `align:"deny"`
	AuthRequirement  policyTypes.AuthRequirement `align:"auth_type"`
	Precedence       policyTypes.Precedence      `align:"precedence"`
	Cookie           uint32                      `align:"cookie"`
}

func (pe PolicyEntry) IsDeny() bool {
	return pe.Flags.is(policyFlagDeny)
}

func (pe *PolicyEntry) String() string {
	prefixLen := pe.Flags.getPrefixLen()
	return fmt.Sprintf("%d %d", pe.GetProxyPort(), prefixLen)
}

func (pe *PolicyEntry) New() bpf.MapValue { return &PolicyEntry{} }

// GetProxyPort returns the ProxyPortNetwork in host byte order
func (pe *PolicyEntry) GetProxyPort() uint16 {
	return byteorder.NetworkToHost16(pe.ProxyPortNetwork)
}

// GetPrefixLen returns the prefix length for the protocol / destination port
func (pe *PolicyEntry) GetPrefixLen() uint8 {
	return pe.Flags.getPrefixLen()
}

type policyEntryFlagParams struct {
	IsDeny    bool
	PrefixLen uint8
}

// getPolicyEntryFlags returns a policyEntryFlags from the policyEntryFlagParams.
func getPolicyEntryFlags(p policyEntryFlagParams) policyEntryFlags {
	var flags policyEntryFlags
	if p.IsDeny {
		flags |= policyFlagDeny
	}
	flags |= policyEntryFlags(p.PrefixLen << policyFlagLPMShift)
	return flags
}

// CallKey is the index into the prog array map.
type CallKey struct {
	Index uint32
}

// CallValue is the program ID in the prog array map.
type CallValue struct {
	ProgID uint32
}

// String converts the key into a human readable string format.
func (k *CallKey) String() string  { return strconv.FormatUint(uint64(k.Index), 10) }
func (k *CallKey) New() bpf.MapKey { return &CallKey{} }

// String converts the value into a human readable string format.
func (v *CallValue) String() string    { return strconv.FormatUint(uint64(v.ProgID), 10) }
func (v *CallValue) New() bpf.MapValue { return &CallValue{} }

// StatsValue holds per-entry policy statistics.
type StatsValue struct {
	Packets uint64 `align:"packets"`
	Bytes   uint64 `align:"bytes"`
}

func (v *StatsValue) String() string {
	return fmt.Sprintf("packets=%d bytes=%d", v.Packets, v.Bytes)
}

// PolicyEntryDump is the policy entry with its key and stats for dumping.
type PolicyEntryDump struct {
	PolicyEntry
	StatsValue
	Key PolicyKey
}

// PolicyEntriesDump is a wrapper for a slice of PolicyEntryDump
type PolicyEntriesDump []PolicyEntryDump

// String returns a string representation of PolicyEntriesDump
func (p PolicyEntriesDump) String() string {
	var sb strings.Builder
	for _, entry := range p {
		sb.WriteString(fmt.Sprintf("%20s: %s %s\n",
			entry.Key.String(), entry.PolicyEntry.String(), entry.StatsValue.String()))
	}
	return sb.String()
}

// Less is a function used to sort PolicyEntriesDump by Policy Type
// (Deny / Allow), TrafficDirection (Ingress / Egress) and Identity
// (ascending order).
func (p PolicyEntriesDump) Less(i, j int) bool {
	iDeny := p[i].PolicyEntry.IsDeny()
	jDeny := p[j].PolicyEntry.IsDeny()
	switch {
	case iDeny && !jDeny:
		return true
	case !iDeny && jDeny:
		return false
	}
	if p[i].Key.TrafficDirection < p[j].Key.TrafficDirection {
		return true
	}
	return p[i].Key.TrafficDirection <= p[j].Key.TrafficDirection &&
		p[i].Key.Identity < p[j].Key.Identity
}

func prefixLenToPortLen(plen uint8) uint16 {
	return 0xffff >> plen
}

func (key *PolicyKey) PortProtoString() string {
	dport := key.GetDestPort()
	protoStr := u8proto.U8proto(key.Nexthdr).String()
	prefixLen := key.GetPrefixLen()
	portPrefixLen := key.GetPortPrefixLen()

	switch {
	case prefixLen == 0, prefixLen == NexthdrBits:
		return protoStr
	case prefixLen > NexthdrBits && prefixLen < FullPrefixBits:
		portLen := prefixLenToPortLen(portPrefixLen)
		return fmt.Sprintf("%d-%d/%s", dport, dport+portLen, protoStr)
	case prefixLen == FullPrefixBits:
		return fmt.Sprintf("%d/%s", dport, protoStr)
	default:
		return fmt.Sprintf("<INVALID PREFIX LENGTH: %d>", prefixLen)
	}
}

func (key *PolicyKey) String() string {
	trafficDirectionString := trafficdirection.TrafficDirection(key.TrafficDirection).String()
	portProtoStr := key.PortProtoString()
	return fmt.Sprintf("%s: %d %s", trafficDirectionString, key.Identity, portProtoStr)
}

func (key *PolicyKey) New() bpf.MapKey { return &PolicyKey{} }

// NewKeyFromPolicyKey converts a policy MapState key to a bpf PolicyMap key.
func NewKeyFromPolicyKey(pk policyTypes.Key) PolicyKey {
	prefixLen := StaticPrefixBits
	if pk.Nexthdr != 0 || pk.DestPort != 0 {
		prefixLen += uint32(NexthdrBits)
		if pk.DestPort != 0 {
			prefixLen += uint32(pk.PortPrefixLen())
		}
	}
	return PolicyKey{
		Prefixlen:        prefixLen,
		Identity:         uint32(pk.Identity),
		TrafficDirection: uint8(pk.TrafficDirection()),
		Nexthdr:          uint8(pk.Nexthdr),
		DestPortNetwork:  byteorder.HostToNetwork16(pk.DestPort),
	}
}

// NewEntryFromPolicyEntry converts a policy MapState entry to a PolicyMap entry.
func NewEntryFromPolicyEntry(key PolicyKey, pe policyTypes.MapStateEntry) PolicyEntry {
	pef := getPolicyEntryFlags(policyEntryFlagParams{
		IsDeny:    pe.IsDeny(),
		PrefixLen: uint8(key.Prefixlen - StaticPrefixBits),
	})

	return PolicyEntry{
		ProxyPortNetwork: byteorder.HostToNetwork16(pe.ProxyPort),
		Flags:            pef,
		AuthRequirement:  pe.AuthRequirement,
		Precedence:       pe.Precedence,
		Cookie:          pe.Cookie,
	}
}

func (v *PolicyEntry) IsValid(k *PolicyKey) bool {
	return v.GetPrefixLen() == uint8(k.Prefixlen-StaticPrefixBits)
}

// parseEndpointID parses the trailing endpoint ID at the end of 'mapPath', separated by '_'.
func parseEndpointID(mapPath string) (uint16, error) {
	if idx := strings.LastIndexByte(mapPath, '_'); idx >= 0 {
		if id64, err := strconv.ParseUint(mapPath[idx+1:], 10, 16); err == nil {
			return uint16(id64), nil
		} else {
			return 0, fmt.Errorf("failed to parse endpoint ID: %w", err)
		}
	}
	return 0, fmt.Errorf("malformed policy map name %q (missing '_')", mapPath)
}

// DumpToMapStateMap converts a policy entries dump to a MapStateMap using generic types.
func DumpToMapStateMap(entries PolicyEntriesDump) policyTypes.MapStateMap {
	out := make(policyTypes.MapStateMap)
	for _, e := range entries {
		key := &e.Key
		val := &e.PolicyEntry

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
	return out
}
