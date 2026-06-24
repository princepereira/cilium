// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package iptables

import "log/slog"

const (
	InpodPreroutingChain        = "CILIUM_PREROUTING"
	InpodOutputChain            = "CILIUM_OUTPUT"
	RouteTableInbound           = 100
	InpodRulePriority           = 32764
	InpodTProxyMark             = 0x111
	InpodMark                   = 0x539
	InpodMask                   = 0xfff
	InpodRestoreMask            = 0xffffffff
	ZtunnelInboundPort          = 15008
	ZtunnelOutboundPort         = 15001
	ZtunnelInboundPlaintextPort = 15006
	VersionSpecificPlaceholder  = "<VERSION_SPECIFIC>"
)

func CreateInPodRules(*slog.Logger, bool, bool) error { return nil }
