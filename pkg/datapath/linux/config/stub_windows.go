// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package config

import (
	"io"

	dpcfg "github.com/cilium/cilium/pkg/datapath/config"
	endpoint "github.com/cilium/cilium/pkg/endpoint/types"
	"github.com/cilium/cilium/pkg/option"
)

type Writer interface {
	WriteNodeConfig(io.Writer, *dpcfg.Config) error
	WriteNetdevConfig(io.Writer, *option.IntOptions) error
	WriteTemplateConfig(io.Writer, endpoint.Config) error
	WriteEndpointConfig(io.Writer, endpoint.Config) error
}

type HeaderfileWriter struct{}

func NewHeaderfileWriter(WriterParams) (Writer, error) { return &HeaderfileWriter{}, nil }
func (*HeaderfileWriter) WriteNodeConfig(io.Writer, *dpcfg.Config) error      { return nil }
func (*HeaderfileWriter) WriteNetdevConfig(io.Writer, *option.IntOptions) error { return nil }
func (*HeaderfileWriter) WriteTemplateConfig(io.Writer, endpoint.Config) error   { return nil }
func (*HeaderfileWriter) WriteEndpointConfig(io.Writer, endpoint.Config) error   { return nil }
