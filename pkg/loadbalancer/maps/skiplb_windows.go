// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package maps

import (
	"iter"
	"log/slog"
	"net"

	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/lock"
)

// SkipLBMap provides access to the store of entries for which load-balancing is skipped.
type SkipLBMap interface {
	AddLB4(netnsCookie uint64, ip net.IP, port uint16) error
	AddLB6(netnsCookie uint64, ip net.IP, port uint16) error
	AllLB4() iter.Seq2[*SkipLB4Key, *SkipLB4Value]
	AllLB6() iter.Seq2[*SkipLB6Key, *SkipLB6Value]
	DeleteLB4(key *SkipLB4Key) error
	DeleteLB6(key *SkipLB6Key) error
	OpenOrCreate() error
	Close() error
}

// NewSkipLBMap returns the Windows implementation of [SkipLBMap].
//
// There is no eBPF skip-LB map on Windows: the datapath is programmed through
// the CNC API which does not expose a skip-LB primitive. The entries are kept
// in-memory so that the local-redirect-policy bookkeeping and reconciliation
// remain consistent; they are not pushed into the kernel datapath.
func NewSkipLBMap(logger *slog.Logger) (SkipLBMap, error) {
	logger.Debug("SkipLB datapath programming not implemented on Windows; tracking in-memory only")
	return &skipLBMap{
		logger: logger,
		lb4:    map[SkipLB4Key]*SkipLB4Value{},
		lb6:    map[SkipLB6Key]*SkipLB6Value{},
	}, nil
}

type skipLBMap struct {
	logger *slog.Logger
	mu     lock.Mutex
	lb4    map[SkipLB4Key]*SkipLB4Value
	lb6    map[SkipLB6Key]*SkipLB6Value
}

func (m *skipLBMap) OpenOrCreate() error { return nil }

func (m *skipLBMap) Close() error { return nil }

// AddLB4 adds the given tuple to the in-memory v4 skip-LB store.
func (m *skipLBMap) AddLB4(netnsCookie uint64, ip net.IP, port uint16) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	// NewSkipLB4Key stores the port in network byte order, matching the Linux map.
	m.lb4[*NewSkipLB4Key(netnsCookie, ip.To4(), port)] = &SkipLB4Value{}
	return nil
}

// AddLB6 adds the given tuple to the in-memory v6 skip-LB store.
func (m *skipLBMap) AddLB6(netnsCookie uint64, ip net.IP, port uint16) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lb6[*NewSkipLB6Key(netnsCookie, ip.To16(), port)] = &SkipLB6Value{}
	return nil
}

func (m *skipLBMap) AllLB4() iter.Seq2[*SkipLB4Key, *SkipLB4Value] {
	return func(yield func(*SkipLB4Key, *SkipLB4Value) bool) {
		m.mu.Lock()
		defer m.mu.Unlock()
		for k, v := range m.lb4 {
			key := k
			key.Port = byteorder.NetworkToHost16(key.Port)
			if !yield(&key, v) {
				return
			}
		}
	}
}

func (m *skipLBMap) AllLB6() iter.Seq2[*SkipLB6Key, *SkipLB6Value] {
	return func(yield func(*SkipLB6Key, *SkipLB6Value) bool) {
		m.mu.Lock()
		defer m.mu.Unlock()
		for k, v := range m.lb6 {
			key := k
			key.Port = byteorder.NetworkToHost16(key.Port)
			if !yield(&key, v) {
				return
			}
		}
	}
}

func (m *skipLBMap) DeleteLB4(key *SkipLB4Key) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := *key
	k.Port = byteorder.HostToNetwork16(k.Port)
	delete(m.lb4, k)
	return nil
}

func (m *skipLBMap) DeleteLB6(key *SkipLB6Key) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := *key
	k.Port = byteorder.HostToNetwork16(k.Port)
	delete(m.lb6, k)
	return nil
}
