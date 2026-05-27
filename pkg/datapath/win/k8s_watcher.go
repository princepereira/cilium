// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package win

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/cilium/hive/cell"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/princepereira/cncshim/pkg/cncapi"
)

// K8sWatcherCell provides the Kubernetes watcher that pushes service/endpoint
// changes to the CNCShim datapath.
var K8sWatcherCell = cell.Module(
	"k8s-watcher-win",
	"Windows K8s Watcher",
	cell.Invoke(startK8sWatcher),
)

// K8sWatcher watches Kubernetes Services and EndpointSlices and programs
// cncshim load-balancer rules accordingly.
type K8sWatcher struct {
	client   *CNCClient
	k8s      kubernetes.Interface
	logger   *slog.Logger
	cancelFn context.CancelFunc

	// mu protects the maps below
	mu sync.Mutex
	// svcBackends tracks current backends per endpointslice name (ns/name)
	svcBackends map[string][]cncapi.BackendInfo
	// createdServices tracks services already created in CNC (by serviceID)
	createdServices map[uint16]bool
}

type k8sWatcherParams struct {
	cell.In

	Client    *CNCClient
	Log       *slog.Logger
	Lifecycle cell.Lifecycle
}

func startK8sWatcher(p k8sWatcherParams) {
	w := &K8sWatcher{
		client:          p.Client,
		logger:          p.Log,
		svcBackends:     make(map[string][]cncapi.BackendInfo),
		createdServices: make(map[uint16]bool),
	}
	p.Lifecycle.Append(w)
}

func (w *K8sWatcher) Start(cell.HookContext) error {
	w.logger.Info("Building K8s config...")
	config, err := buildK8sConfig()
	if err != nil {
		w.logger.Error("Failed to build K8s config", "error", err)
		return fmt.Errorf("failed to build k8s config: %w", err)
	}
	w.logger.Info("K8s config built successfully", "host", config.Host)

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		w.logger.Error("Failed to create K8s clientset", "error", err)
		return fmt.Errorf("failed to create k8s clientset: %w", err)
	}
	w.k8s = clientset

	ctx, cancel := context.WithCancel(context.Background())
	w.cancelFn = cancel

	go w.watchServices(ctx)
	go w.watchEndpointSlices(ctx)

	w.logger.Info("K8s watchers started")
	return nil
}

func (w *K8sWatcher) Stop(cell.HookContext) error {
	if w.cancelFn != nil {
		w.cancelFn()
	}
	w.logger.Info("K8s watchers stopped")
	return nil
}

func buildK8sConfig() (*rest.Config, error) {
	// Try in-cluster config first (running inside a pod)
	config, err := rest.InClusterConfig()
	if err == nil {
		return config, nil
	}

	// Fall back to kubeconfig
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	configOverrides := &clientcmd.ConfigOverrides{}
	kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides)
	return kubeConfig.ClientConfig()
}

func (w *K8sWatcher) watchServices(ctx context.Context) {
	backoff := time.Second
	for {
		if err := w.doWatchServices(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			w.logger.Error("Service watch error, restarting", "error", err, "retryIn", backoff)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			if backoff < 30*time.Second {
				backoff *= 2
			}
		} else {
			backoff = time.Second
		}
	}
}

func (w *K8sWatcher) doWatchServices(ctx context.Context) error {
	watcher, err := w.k8s.CoreV1().Services("").Watch(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("watch services: %w", err)
	}
	defer watcher.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case event, ok := <-watcher.ResultChan():
			if !ok {
				return fmt.Errorf("service watch channel closed")
			}
			svc, ok := event.Object.(*corev1.Service)
			if !ok {
				continue
			}
			switch event.Type {
			case watch.Added, watch.Modified:
				w.onServiceUpsert(svc)
			case watch.Deleted:
				w.onServiceDelete(svc)
			}
		}
	}
}

func (w *K8sWatcher) onServiceUpsert(svc *corev1.Service) {
	api := w.client.API()
	if api == nil {
		return
	}

	clusterIP, err := netip.ParseAddr(svc.Spec.ClusterIP)
	if err != nil {
		return
	}

	for _, port := range svc.Spec.Ports {
		frontend := cncapi.FrontendInfo{
			IPAddress: clusterIP,
			Port:      uint16(port.Port),
			Protocol:  protocolToUint8(port.Protocol),
		}

		svcType := cncapi.ServiceTypeClusterIP
		switch svc.Spec.Type {
		case corev1.ServiceTypeNodePort:
			svcType = cncapi.ServiceTypeNodePort
		case corev1.ServiceTypeLoadBalancer:
			svcType = cncapi.ServiceTypeLoadBalancer
		}

		lbInfo := &cncapi.LoadBalancerInfo{
			ServiceType: svcType,
			Frontend:    frontend,
		}

		serviceID := servicePortID(svc, port)

		// Skip if already created — CNC re-creates on duplicate call, wiping backends
		w.mu.Lock()
		alreadyCreated := w.createdServices[serviceID]
		w.mu.Unlock()
		if alreadyCreated {
			continue
		}

		w.logger.Info("DEBUG CreateLoadBalancerService",
			"service", svc.Namespace+"/"+svc.Name,
			"serviceID", serviceID,
			"serviceType", svcType,
			"frontendIP", clusterIP.String(),
			"frontendPort", port.Port,
			"frontendProto", protocolToUint8(port.Protocol),
		)
		if err := api.CreateLoadBalancerService(serviceID, lbInfo); err != nil {
			if isAlreadyExistsErr(err) {
				w.mu.Lock()
				w.createdServices[serviceID] = true
				w.mu.Unlock()
			} else {
				w.logger.Error("Failed to create LB service",
					"service", svc.Namespace+"/"+svc.Name,
					"port", port.Port,
					"error", err)
			}
		} else {
			w.mu.Lock()
			w.createdServices[serviceID] = true
			w.mu.Unlock()
			w.logger.Info("LB service created",
				"service", svc.Namespace+"/"+svc.Name,
				"clusterIP", svc.Spec.ClusterIP,
				"port", port.Port)
		}
	}
}

func (w *K8sWatcher) onServiceDelete(svc *corev1.Service) {
	api := w.client.API()
	if api == nil {
		return
	}

	clusterIP, err := netip.ParseAddr(svc.Spec.ClusterIP)
	if err != nil {
		return
	}

	for _, port := range svc.Spec.Ports {
		frontend := cncapi.FrontendInfo{
			IPAddress: clusterIP,
			Port:      uint16(port.Port),
			Protocol:  protocolToUint8(port.Protocol),
		}

		lbInfo := &cncapi.LoadBalancerInfo{
			Frontend: frontend,
		}

		serviceID := servicePortID(svc, port)
		if err := api.DeleteLoadBalancerService(serviceID, lbInfo); err != nil {
			w.logger.Error("Failed to delete LB service",
				"service", svc.Namespace+"/"+svc.Name,
				"error", err)
		} else {
			w.mu.Lock()
			delete(w.createdServices, serviceID)
			w.mu.Unlock()
			w.logger.Info("LB service deleted",
				"service", svc.Namespace+"/"+svc.Name)
		}
	}
}

func (w *K8sWatcher) watchEndpointSlices(ctx context.Context) {
	backoff := time.Second
	for {
		if err := w.doWatchEndpointSlices(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			w.logger.Error("EndpointSlice watch error, restarting", "error", err, "retryIn", backoff)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			if backoff < 30*time.Second {
				backoff *= 2
			}
		} else {
			backoff = time.Second
		}
	}
}

func (w *K8sWatcher) doWatchEndpointSlices(ctx context.Context) error {
	watcher, err := w.k8s.DiscoveryV1().EndpointSlices("").Watch(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("watch endpointslices: %w", err)
	}
	defer watcher.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case event, ok := <-watcher.ResultChan():
			if !ok {
				return fmt.Errorf("endpointslice watch channel closed")
			}
			eps, ok := event.Object.(*discoveryv1.EndpointSlice)
			if !ok {
				continue
			}
			switch event.Type {
			case watch.Added, watch.Modified:
				w.onEndpointSliceUpsert(eps)
			case watch.Deleted:
				w.onEndpointSliceDelete(eps)
			}
		}
	}
}

func (w *K8sWatcher) onEndpointSliceUpsert(eps *discoveryv1.EndpointSlice) {
	api := w.client.API()
	if api == nil {
		return
	}

	epsKey := eps.Namespace + "/" + eps.Name

	// Build desired backends from the EndpointSlice
	type ipPort struct {
		ip   netip.Addr
		port uint16
	}
	desiredSet := make(map[ipPort]struct{})
	for _, ep := range eps.Endpoints {
		if ep.Conditions.Ready != nil && !*ep.Conditions.Ready {
			continue
		}
		for _, addr := range ep.Addresses {
			ip, err := netip.ParseAddr(addr)
			if err != nil {
				continue
			}
			for _, port := range eps.Ports {
				if port.Port == nil {
					continue
				}
				desiredSet[ipPort{ip: ip, port: uint16(*port.Port)}] = struct{}{}
			}
		}
	}

	// Get old backends for this endpointslice
	w.mu.Lock()
	oldBackends := w.svcBackends[epsKey]
	w.mu.Unlock()

	// Build set of old IP:ports
	oldSet := make(map[ipPort]cncapi.BackendInfo, len(oldBackends))
	for _, b := range oldBackends {
		oldSet[ipPort{ip: b.IPAddress, port: b.Port}] = b
	}

	// Compute diff: added and removed
	var added []ipPort
	for ep := range desiredSet {
		if _, exists := oldSet[ep]; !exists {
			added = append(added, ep)
		}
	}
	var removed []cncapi.BackendInfo
	for ep, b := range oldSet {
		if _, exists := desiredSet[ep]; !exists {
			removed = append(removed, b)
		}
	}

	// No change — skip
	if len(added) == 0 && len(removed) == 0 {
		return
	}

	// Determine the service this endpointslice belongs to
	svcName := eps.Labels["kubernetes.io/service-name"]
	if svcName == "" {
		w.logger.Warn("EndpointSlice missing service-name label", "endpointslice", epsKey)
		return
	}

	// Allocate deterministic IDs based on IP:Port hash so the same backend
	// always gets the same ID (survives agent restarts / "already exists" in CNC)
	var addedBackends []cncapi.BackendInfo
	for _, ep := range added {
		addedBackends = append(addedBackends, cncapi.BackendInfo{
			BackendID: backendIDFromAddr(ep.ip, ep.port),
			IPAddress: ep.ip,
			Port:      ep.port,
		})
	}

	if len(addedBackends) > 0 {
		for i, b := range addedBackends {
			w.logger.Info("DEBUG CreateLoadBalancerBackends",
				"endpointslice", epsKey,
				"index", i,
				"backendID", b.BackendID,
				"ip", b.IPAddress.String(),
				"port", b.Port,
			)
		}
		if err := api.CreateLoadBalancerBackends(addedBackends); err != nil {
			if !isAlreadyExistsErr(err) {
				w.logger.Error("Failed to create LB backends",
					"endpointslice", epsKey, "error", err)
				return
			}
			// "Already exists" is fine — backend IP:Port is already in CNC with same ID
		}
	}

	// Link backends to service via UpdateLoadBalancerServiceBackends.
	// This is a SWAP API: pass the full new set and the full old set.
	if len(addedBackends) > 0 || len(removed) > 0 {
		svc, err := w.k8s.CoreV1().Services(eps.Namespace).Get(context.Background(), svcName, metav1.GetOptions{})
		if err != nil {
			w.logger.Error("Failed to get service for EndpointSlice",
				"endpointslice", epsKey, "service", svcName, "error", err)
			return
		}

		// Compute the full new backend set (unchanged + added)
		var allNewBackends []cncapi.BackendInfo
		for _, b := range oldBackends {
			key := ipPort{ip: b.IPAddress, port: b.Port}
			if _, stillDesired := desiredSet[key]; stillDesired {
				allNewBackends = append(allNewBackends, b)
			}
		}
		allNewBackends = append(allNewBackends, addedBackends...)

		for _, port := range svc.Spec.Ports {
			clusterIP, err := netip.ParseAddr(svc.Spec.ClusterIP)
			if err != nil {
				continue
			}
			frontend := cncapi.FrontendInfo{
				IPAddress: clusterIP,
				Port:      uint16(port.Port),
				Protocol:  protocolToUint8(port.Protocol),
			}
			svcType := cncapi.ServiceTypeClusterIP
			switch svc.Spec.Type {
			case corev1.ServiceTypeNodePort:
				svcType = cncapi.ServiceTypeNodePort
			case corev1.ServiceTypeLoadBalancer:
				svcType = cncapi.ServiceTypeLoadBalancer
			}
			lbInfo := &cncapi.LoadBalancerInfo{
				ServiceType: svcType,
				Frontend:    frontend,
			}
			serviceID := servicePortID(svc, port)

			w.logger.Info("DEBUG UpdateLoadBalancerServiceBackends",
				"endpointslice", epsKey,
				"service", eps.Namespace+"/"+svcName,
				"serviceID", serviceID,
				"serviceType", svcType,
				"frontendIP", clusterIP.String(),
				"frontendPort", port.Port,
				"frontendProto", protocolToUint8(port.Protocol),
				"newBackendsCount", len(allNewBackends),
				"oldBackendsCount", len(oldBackends),
			)

			if err := api.UpdateLoadBalancerServiceBackends(serviceID, lbInfo, allNewBackends, oldBackends); err != nil {
				w.logger.Error("Failed to update LB backends",
					"endpointslice", epsKey,
					"service", eps.Namespace+"/"+svcName,
					"serviceID", serviceID,
					"error", err)
			}
		}
	}

	// Delete removed backend entries from CNC global table
	if len(removed) > 0 {
		var ids4, ids6 []uint32
		for _, b := range removed {
			if b.IPAddress.Is4() {
				ids4 = append(ids4, b.BackendID)
			} else {
				ids6 = append(ids6, b.BackendID)
			}
		}
		if len(ids4) > 0 {
			_ = api.DeleteLoadBalancerBackends(2, ids4)
		}
		if len(ids6) > 0 {
			_ = api.DeleteLoadBalancerBackends(23, ids6)
		}
	}

	w.logger.Info("LB backends reconciled",
		"endpointslice", epsKey,
		"added", len(addedBackends),
		"removed", len(removed))

	// Update stored state: keep unchanged + add new
	w.mu.Lock()
	var current []cncapi.BackendInfo
	// Keep backends that are still desired
	for _, b := range oldBackends {
		key := ipPort{ip: b.IPAddress, port: b.Port}
		if _, stillDesired := desiredSet[key]; stillDesired {
			current = append(current, b)
		}
	}
	// Add newly created backends
	current = append(current, addedBackends...)
	if len(current) > 0 {
		w.svcBackends[epsKey] = current
	} else {
		delete(w.svcBackends, epsKey)
	}
	w.mu.Unlock()
}


func (w *K8sWatcher) onEndpointSliceDelete(eps *discoveryv1.EndpointSlice) {
	api := w.client.API()
	if api == nil {
		return
	}

	epsKey := eps.Namespace + "/" + eps.Name

	w.mu.Lock()
	oldBackends := w.svcBackends[epsKey]
	delete(w.svcBackends, epsKey)
	w.mu.Unlock()

	if len(oldBackends) > 0 {
		// Delete the backends by their IDs
		var ids4, ids6 []uint32
		for _, b := range oldBackends {
			if b.IPAddress.Is4() {
				ids4 = append(ids4, b.BackendID)
			} else {
				ids6 = append(ids6, b.BackendID)
			}
		}
		if len(ids4) > 0 {
			if err := api.DeleteLoadBalancerBackends(2, ids4); err != nil { // AF_INET=2
				w.logger.Error("Failed to delete IPv4 backends", "endpointslice", epsKey, "error", err)
			}
		}
		if len(ids6) > 0 {
			if err := api.DeleteLoadBalancerBackends(23, ids6); err != nil { // AF_INET6=23
				w.logger.Error("Failed to delete IPv6 backends", "endpointslice", epsKey, "error", err)
			}
		}
	}

	w.logger.Info("EndpointSlice deleted", "endpointslice", epsKey, "backendsRemoved", len(oldBackends))
}

// servicePortID generates a stable uint16 service ID from service UID + port.
func servicePortID(svc *corev1.Service, port corev1.ServicePort) uint16 {
	// FNV-1a hash over UID bytes + port to ensure unique IDs per service+port
	var h uint32 = 2166136261
	for _, c := range []byte(svc.UID) {
		h ^= uint32(c)
		h *= 16777619
	}
	h ^= uint32(port.Port)
	h *= 16777619
	// Fold 32-bit into 16-bit
	id := uint16(h) ^ uint16(h>>16)
	if id == 0 {
		id = 1
	}
	return id
}

func protocolToUint8(p corev1.Protocol) uint8 {
	switch p {
	case corev1.ProtocolTCP:
		return 6
	case corev1.ProtocolUDP:
		return 17
	case corev1.ProtocolSCTP:
		return 132
	default:
		return 6
	}
}

// isAlreadyExistsErr checks if the error is an "already exists" HRESULT (0x800700B7).
func isAlreadyExistsErr(err error) bool {
	return err != nil && strings.Contains(err.Error(), "0x800700B7")
}

// backendIDFromAddr generates a deterministic uint32 backend ID from IP:Port.
// This ensures the same backend always gets the same ID regardless of agent restarts,
// which is critical because CNC identifies backends by ID and rejects mismatches.
func backendIDFromAddr(ip netip.Addr, port uint16) uint32 {
	b := ip.As16()
	// FNV-1a style hash
	var h uint32 = 2166136261
	for _, c := range b {
		h ^= uint32(c)
		h *= 16777619
	}
	h ^= uint32(port)
	h *= 16777619
	if h == 0 {
		h = 1
	}
	return h
}
