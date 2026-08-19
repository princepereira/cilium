// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bandwidth

import "k8s.io/apimachinery/pkg/api/resource"

const (
	// EgressBandwidth is the K8s Pod annotation.
	EgressBandwidth = "kubernetes.io/egress-bandwidth"
	// IngressBandwidth is the K8s Pod annotation.
	IngressBandwidth = "kubernetes.io/ingress-bandwidth"
	// Priority is the Cilium Pod priority annotation.
	Priority = "bandwidth.cilium.io/priority"

	// FQ priomap starting from index 0 is 1 2 2 2 1 2 0 0 1 1 1 1 1 1 1 1
	// Constants below map priority levels to bands high, medium and low.
	// TODO: These are picked arbitrarily for each QoS class amongst different possible
	// values. Revisit to see if picking these values would have any unintended side effects.
	// HACK: Increment prio values by 1 to allow for distinguishing between 0 prio and no prio set.

	// GuaranteedQoSDefaultPriority prio value to classify packets to high prio band
	GuaranteedQoSDefaultPriority = 6 + 1
	// BurstableQoSDefaultPriority prio value to classify packets to medium prio band
	BurstableQoSDefaultPriority = 8 + 1
	// BestEffortQoSDefaultPriority prio value to classify packets to medium prio band
	BestEffortQoSDefaultPriority = 5 + 1
)

// GetBytesPerSec parses a K8s bandwidth quantity string and returns the
// corresponding number of bytes per second.
func GetBytesPerSec(bandwidth string) (uint64, error) {
	res, err := resource.ParseQuantity(bandwidth)
	if err != nil {
		return 0, err
	}
	return uint64(res.Value() / 8), err
}

// Manager is the interface implemented by the Linux bandwidth manager. It is
// declared in a platform-neutral file so that consumers can reference the type
// on all platforms, while the implementation remains Linux-only.
type Manager interface {
	BBREnabled() bool
	Enabled() bool

	UpdateBandwidthLimit(endpointID uint16, bytesPerSecond uint64, prio uint32)
	DeleteBandwidthLimit(endpointID uint16)

	UpdateIngressBandwidthLimit(endpointID uint16, bytesPerSecond uint64)
	DeleteIngressBandwidthLimit(endpointID uint16)
}
