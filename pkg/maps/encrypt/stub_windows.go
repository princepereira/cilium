// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package encrypt

import (
	"github.com/cilium/hive/cell"

	ipsec "github.com/cilium/cilium/pkg/datapath/linux/ipsec/types"
	"github.com/cilium/cilium/pkg/option"
)

type EncryptKey struct {
	Key uint32 `align:"ctx"`
}

type EncryptValue struct {
	KeyID uint8
}

func (k EncryptKey) String() string   { return "" }
func (v EncryptValue) String() string { return "" }

const MapName = "cilium_encrypt_state"

type encryptMap struct{}

func newMap(cell.Lifecycle, ipsec.Config, *option.DaemonConfig) *encryptMap { return &encryptMap{} }
func (m *encryptMap) Update(EncryptKey, EncryptValue) error      { return nil }
func (m *encryptMap) Lookup(EncryptKey) (EncryptValue, error)    { return EncryptValue{}, nil }
func (m *encryptMap) UnpinIfExists() error                       { return nil }
