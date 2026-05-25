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
}

type k8sWatcherParams struct {
	cell.In

	Client    *CNCClient
	Log       *slog.Logger
	Lifecycle cell.Lifecycle
}

func startK8sWatcher(p k8sWatcherParams) {
	w := &K8sWatcher{
		client: p.Client,
		logger: p.Log,
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
		if err := api.CreateLoadBalancerService(serviceID, lbInfo); err != nil {
			if isAlreadyExistsErr(err) {
				w.logger.Info("LB service already exists, skipping",
					"service", svc.Namespace+"/"+svc.Name,
					"port", port.Port)
			} else {
				w.logger.Error("Failed to create LB service",
					"service", svc.Namespace+"/"+svc.Name,
					"port", port.Port,
					"error", err)
			}
		} else {
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

	var backends []cncapi.BackendInfo
	var backendID uint32

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
				backendID++
				backends = append(backends, cncapi.BackendInfo{
					BackendID: backendID,
					IPAddress: ip,
					Port:      uint16(*port.Port),
				})
			}
		}
	}

	if len(backends) > 0 {
		if err := api.CreateLoadBalancerBackends(backends); err != nil {
			if isAlreadyExistsErr(err) {
				w.logger.Info("LB backends already exist, skipping",
					"endpointslice", eps.Namespace+"/"+eps.Name,
					"count", len(backends))
			} else {
				w.logger.Error("Failed to create LB backends",
					"endpointslice", eps.Namespace+"/"+eps.Name,
					"error", err)
			}
		} else {
			w.logger.Info("LB backends updated",
				"endpointslice", eps.Namespace+"/"+eps.Name,
				"count", len(backends))
		}
	}
}

func (w *K8sWatcher) onEndpointSliceDelete(eps *discoveryv1.EndpointSlice) {
	// On delete, backends will be cleaned up by service deletion
	w.logger.Info("EndpointSlice deleted",
		"endpointslice", eps.Namespace+"/"+eps.Name)
}

// servicePortID generates a stable uint16 service ID from service UID + port.
func servicePortID(svc *corev1.Service, port corev1.ServicePort) uint16 {
	// Simple hash: use port number as part of ID
	// In production this should use a proper allocator
	h := uint16(port.Port) ^ uint16(len(svc.UID))
	if h == 0 {
		h = 1
	}
	return h
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
