// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package api

import (
	"bufio"

	"github.com/cilium/cilium/pkg/hubble/parser/getters"
)

type Verbosity uint8

type DisplayFormat bool

const (
	INFO Verbosity = iota + 1
	DEBUG
	VERBOSE
	JSON
)

const (
	DisplayLabel   DisplayFormat = false
	DisplayNumeric DisplayFormat = true
)

type DumpArgs struct {
	Data        []byte
	CpuPrefix   string
	Format      DisplayFormat
	LinkMonitor getters.LinkGetter
	Dissect     bool
	Verbosity   Verbosity
	Buf         *bufio.Writer
}

type DefaultSrcDstGetter struct{}

func (d *DefaultSrcDstGetter) GetSrc() (src uint16) { return 0 }
func (d *DefaultSrcDstGetter) GetDst() (dst uint16) { return 0 }
