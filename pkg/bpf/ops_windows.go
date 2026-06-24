// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package bpf

import (
	"context"
	"encoding"
	"errors"
	"iter"
	"reflect"
	"unsafe"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
)

// ErrMapNotOpened is returned when the MapOps is used with a BPF map that is not open yet.
var ErrMapNotOpened = errors.New("BPF map has not been opened")

// KeyValue is the interface that a BPF map value object must implement.
type KeyValue interface {
	BinaryKey() encoding.BinaryMarshaler
	BinaryValue() encoding.BinaryMarshaler
}

// StructBinaryMarshaler implements a BinaryMarshaler for a struct.
type StructBinaryMarshaler struct {
	Target any
}

func (m StructBinaryMarshaler) MarshalBinary() ([]byte, error) {
	v := reflect.ValueOf(m.Target)
	size := int(v.Type().Elem().Size())
	return unsafe.Slice((*byte)(v.UnsafePointer()), size), nil
}

type mapOps[KV KeyValue] struct {
	m *Map
}

func NewMapOps[KV KeyValue](m *Map) reconciler.Operations[KV] {
	return &mapOps[KV]{m}
}

func (ops *mapOps[KV]) Delete(ctx context.Context, txn statedb.ReadTxn, _ statedb.Revision, entry KV) error {
	return nil
}

func (ops *mapOps[KV]) Update(ctx context.Context, txn statedb.ReadTxn, _ statedb.Revision, entry KV) error {
	return nil
}

func (ops *mapOps[KV]) Prune(ctx context.Context, txn statedb.ReadTxn, objects iter.Seq2[KV, statedb.Revision]) error {
	return nil
}
