// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package maps

import (
	"iter"
	"log/slog"
	"net"
)

// NewSkipLBMap returns a no-op SkipLBMap on Windows.
// The skip-LB feature relies on Linux BPF maps and netns cookies, which are
// not available on Windows. All operations on the returned map are no-ops.
func NewSkipLBMap(_ *slog.Logger) (SkipLBMap, error) {
	return &noopSkipLBMap{}, nil
}

// noopSkipLBMap is a Windows stub that satisfies the SkipLBMap interface.
type noopSkipLBMap struct{}

func (n *noopSkipLBMap) OpenOrCreate() error { return nil }
func (n *noopSkipLBMap) Close() error        { return nil }
func (n *noopSkipLBMap) AllLB4() iter.Seq2[*SkipLB4Key, *SkipLB4Value] {
	return func(yield func(*SkipLB4Key, *SkipLB4Value) bool) {}
}
func (n *noopSkipLBMap) AllLB6() iter.Seq2[*SkipLB6Key, *SkipLB6Value] {
	return func(yield func(*SkipLB6Key, *SkipLB6Value) bool) {}
}
func (n *noopSkipLBMap) AddLB4(_ uint64, _ net.IP, _ uint16) error     { return nil }
func (n *noopSkipLBMap) AddLB6(_ uint64, _ net.IP, _ uint16) error     { return nil }
func (n *noopSkipLBMap) DeleteLB4(_ *SkipLB4Key) error                 { return nil }
func (n *noopSkipLBMap) DeleteLB6(_ *SkipLB6Key) error                 { return nil }

var _ SkipLBMap = &noopSkipLBMap{}
