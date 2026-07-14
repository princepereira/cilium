// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package cmd

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"google.golang.org/grpc"

	"github.com/cilium/cilium/api/v1/server"
	"github.com/cilium/cilium/daemon/healthz"
	"github.com/cilium/cilium/daemon/restapi"
	"github.com/cilium/cilium/pkg/api"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	linuxdatapath "github.com/cilium/cilium/pkg/datapath/linux"
	datapathTables "github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/dial"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	k8sSynced "github.com/cilium/cilium/pkg/k8s/synced"
	k8sTables "github.com/cilium/cilium/pkg/k8s/tables"
	k8s "github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/watchers"
	"github.com/cilium/cilium/pkg/k8s/watchers/resources"
	"github.com/cilium/cilium/pkg/kpr"
	"github.com/cilium/cilium/pkg/kvstore"
	loadbalancer_cell "github.com/cilium/cilium/pkg/loadbalancer/cell"
	lbipamconfig "github.com/cilium/cilium/pkg/lbipamconfig"
	"github.com/cilium/cilium/pkg/maglev"
	nodeipamconfig "github.com/cilium/cilium/pkg/nodeipamconfig"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	nodeManager "github.com/cilium/cilium/pkg/node/manager"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/pprof"
	"github.com/cilium/cilium/pkg/source"
)

var (
	Agent = cell.Module(
		"agent",
		"Cilium Agent",

		Infrastructure,
		ControlPlane,
	)

	// Infrastructure provides access and services to the outside.
	// A cell should live here instead of ControlPlane if it is not needed by
	// integrations tests, or needs to be mocked.
	Infrastructure = cell.Module(
		"windows-infra",
		"Minimal Windows agent infrastructure",

		// Provides the global DaemonConfig to the hive so that cells such as
		// the Kubernetes client can depend on the agent configuration.
		cell.Provide(func() *option.DaemonConfig { return option.Config }),

		// Minimal stub status collector for the health endpoints.
		cell.Provide(newWindowsStatusCollector),

		// Kube-proxy replacement config (needed by the health endpoints).
		kpr.Cell,

		// Local node store with a no-op synchronizer for minimal bring-up.
		cell.Provide(node.NewNopLocalNodeSynchronizer),
		node.LocalNodeStoreCell,

		// Data source priorities, required by the load-balancer writer.
		source.Cell,

		// Device, route and neighbor tables (stubbed on Windows) and the
		// derived node-address table, required by the load-balancer writer.
		linuxdatapath.DevicesControllerCell,
		datapathTables.NodeAddressCell,

		// StateDB tables of Kubernetes objects (pods, namespaces) reflected
		// from the API server, required by the load-balancer reflectors.
		k8sTables.TablesCell,

		// Configuration for the k8s resource reflectors used by the
		// load-balancer control plane.
		cell.Config(k8s.DefaultConfig),
		cell.Provide(k8s.DefaultServiceWatchConfig),

		// LB-IPAM / Node-IPAM configuration required by the load-balancer
		// external configuration.
		lbipamconfig.Cell,
		nodeipamconfig.Cell,

		// Maglev table computations required by the load-balancer BPF reconciler.
		maglev.Cell,

		// Provides Clientset, API for accessing Kubernetes objects.
		k8sClient.Cell,

		// Cilium Agent Healthz endpoints (agent, kubeproxy, ...)
		healthz.Cell,
	)

	// ControlPlane implement the per-node control functions. These are pure
	// business logic and depend on datapath or infrastructure to perform
	// actions. This separation enables non-privileged integration testing of
	// the control-plane.
	ControlPlane = cell.Module(
		"windows-controlplane",
		"Minimal Windows control plane",

		// Control-plane for configuring service load-balancing
		loadbalancer_cell.Cell,

		// Registers the clustermesh cluster identity flags (cluster-id,
		// cluster-name, max-connected-clusters) with their defaults so that
		// daemon config validation succeeds.
		cell.Config(cmtypes.DefaultClusterInfo),

		// Cilium REST API handlers
		restapi.Cell,
	)
)

func configureAPIServer(cfg *option.DaemonConfig, s *server.Server, db *statedb.DB, swaggerSpec *server.Spec, logger *slog.Logger) {
	s.EnabledListeners = []string{"unix"}
	s.SocketPath = cfg.SocketPath
	s.ReadTimeout = apiTimeout
	s.WriteTimeout = apiTimeout

	const msg = "Required API option is disabled. This may prevent Cilium from operating correctly"
	hint := "Consider enabling this API in " + server.AdminEnableFlag
	for _, requiredAPI := range []string{
		"GetConfig",        // CNI: Used to detect detect IPAM mode
		"GetHealthz",       // Kubelet: daemon health checks
		"PutEndpointID",    // CNI: Provision the network for a new Pod
		"DeleteEndpointID", // CNI: Clean up networking for a deleted Pod
		"PostIPAM",         // CNI: Reserve IPs for new Pods
		"DeleteIPAMIP",     // CNI: Release IPs for deleted Pods
	} {
		if _, denied := swaggerSpec.DeniedAPIs[requiredAPI]; denied {
			logger.Warn(
				msg,
				logfields.Hint, hint,
				logfields.Params, requiredAPI,
			)
		}
	}
	api.DisableAPIs(logger, swaggerSpec.DeniedAPIs, s.GetAPI().AddMiddlewareFor)

	s.ConfigureAPI()

	// Add the /statedb HTTP handler
	mux := http.NewServeMux()
	mux.Handle("/", s.GetHandler())
	mux.Handle("/statedb/", http.StripPrefix("/statedb", db.HTTPHandler()))
	s.SetHandler(mux)
}

var pprofConfig = pprof.Config{
	Pprof:                     false,
	PprofAddress:              option.PprofAddressAgent,
	PprofPort:                 option.PprofPortAgent,
	PprofMutexProfileFraction: 0,
	PprofBlockProfileRate:     0,
}

// resourceGroups are all of the core Kubernetes and Cilium resource groups
// which the Cilium agent watches to implement CNI functionality.
func allResourceGroups(logger *slog.Logger, cfg watchers.WatcherConfiguration) (resourceGroups, waitForCachesOnly []string) {
	k8sGroups := []string{
		// Pods can contain labels which are essential for endpoints
		// being restored to have the right identity.
		resources.K8sAPIGroupPodV1Core,
	}

	if cfg.K8sNetworkPolicyEnabled() {
		// When the flag is set,
		// We need all network policies in place before restoring to
		// make sure we are enforcing the correct policies for each
		// endpoint before restarting.
		waitForCachesOnly = append(waitForCachesOnly, resources.K8sAPIGroupNetworkingV1Core)
	}

	ciliumGroups, waitOnlyList := watchers.GetGroupsForCiliumResources(logger, k8sSynced.AgentCRDResourceNames())
	waitForCachesOnly = append(waitForCachesOnly, waitOnlyList...)

	return append(k8sGroups, ciliumGroups...), waitForCachesOnly
}

// kvstoreExtraOptions provides the extra options to initialize the kvstore client.
func kvstoreExtraOptions(in struct {
	cell.In

	Logger *slog.Logger

	NodeManager nodeManager.NodeManager
	ClientSet   k8sClient.Clientset
	Resolver    dial.Resolver
},
) kvstore.ExtraOptions {
	goopts := kvstore.ExtraOptions{
		ClusterSizeDependantInterval: in.NodeManager.ClusterSizeDependantInterval,
	}

	// If K8s is enabled we can do the service translation automagically by
	// looking at services from k8s and retrieve the service IP from that.
	// This makes cilium to not depend on kube dns to interact with etcd
	if in.ClientSet.IsEnabled() {
		goopts.DialOption = []grpc.DialOption{
			grpc.WithContextDialer(dial.NewContextDialer(in.Logger, in.Resolver)),
		}
	}

	return goopts
}

// kvstoreLocksGC registers the kvstore locks GC logic.
func kvstoreLocksGC(logger *slog.Logger, jg job.Group, client kvstore.Client) {
	if client.IsEnabled() {
		jg.Add(job.Timer("kvstore-locks-gc", func(ctx context.Context) error {
			kvstore.RunLockGC(logger)
			return nil
		}, defaults.KVStoreStaleLockTimeout))
	}
}
