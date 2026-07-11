// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package ipsec

import (
	"errors"
	"log/slog"
	"net"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	"github.com/cilium/cilium/pkg/datapath/linux/ipsec/types"
	"github.com/cilium/cilium/pkg/maps/encrypt"
	"github.com/cilium/cilium/pkg/node"
)

var errIPsecUnsupported = errors.New("IPsec is unsupported on non-Linux platforms")

type agent struct{}

var _ types.Agent = (*agent)(nil)

func newAgent(cell.Lifecycle, *slog.Logger, job.Group, *node.LocalNodeStore, config, encrypt.EncryptMap) *agent {
	return &agent{}
}

func (a *agent) Enabled() bool {
	return false
}

func (a *agent) AuthKeySize() int {
	return 0
}

func (a *agent) StartBackgroundJobs(node.Handler, <-chan struct{}) error {
	return nil
}

func (a *agent) UpsertIPsecEndpoint(params *types.Parameters) (uint8, error) {
	return 0, errIPsecUnsupported
}

func (a *agent) DeleteIPsecEndpoint(nodeID uint16) error {
	return nil
}

func (a *agent) DeleteXFRM(reqID int) error {
	return nil
}

func (a *agent) DeleteXfrmPolicyOut(nodeID uint16, dst *net.IPNet) error {
	return nil
}
