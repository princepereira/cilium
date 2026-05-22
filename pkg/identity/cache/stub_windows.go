// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package cache

import (
	"context"
	"log/slog"
	"path"

	"github.com/cilium/stream"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/allocator"
	"github.com/cilium/cilium/pkg/identity"
	identitymodel "github.com/cilium/cilium/pkg/identity/model"
	"github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/time"
)

var IdentitiesPath = path.Join(kvstore.BaseKeyPrefix, "state", "identities", "v1")

const CheckpointFile = "local_allocator_state.json"

type IdentitiesModel []*models.Identity

func (s IdentitiesModel) Len() int           { return len(s) }
func (s IdentitiesModel) Less(i, j int) bool { return s[i].ID < s[j].ID }
func (s IdentitiesModel) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }

func (s IdentitiesModel) FromIdentityCache(cache identity.IdentityMap) IdentitiesModel {
	for id, lbls := range cache {
		s = append(s, identitymodel.CreateModel(&identity.Identity{ID: id, Labels: lbls.Labels()}))
	}
	return s
}

type AllocatorConfig struct {
	EnableOperatorManageCIDs bool
	Timeout                  time.Duration
	SyncInterval             time.Duration
	maxAllocAttempts         int
}

func NewTestAllocatorConfig() AllocatorConfig {
	return AllocatorConfig{Timeout: 5 * time.Second, SyncInterval: time.Hour}
}

type IdentityAllocatorOwner interface {
	UpdateIdentities(added, deleted identity.IdentityMap) <-chan struct{}
	GetNodeSuffix() string
}

type IdentityAllocator interface {
	stream.Observable[IdentityChange]
	WaitForInitialGlobalIdentities(context.Context) error
	AllocateIdentity(context.Context, labels.Labels, bool, identity.NumericIdentity) (*identity.Identity, bool, error)
	AllocateLocalIdentity(labels.Labels, bool, identity.NumericIdentity) (*identity.Identity, bool, error)
	Release(context.Context, *identity.Identity, bool) (released bool, err error)
	ReleaseLocalIdentities(...identity.NumericIdentity) ([]identity.NumericIdentity, error)
	LookupIdentity(context.Context, labels.Labels) *identity.Identity
	LookupIdentityByID(context.Context, identity.NumericIdentity) *identity.Identity
	GetIdentityCache() identity.IdentityMap
	GetIdentities() IdentitiesModel
	WithholdLocalIdentities([]identity.NumericIdentity)
	UnwithholdLocalIdentities([]identity.NumericIdentity)
}

type IdentityChangeKind string

const (
	IdentityChangeSync   IdentityChangeKind = IdentityChangeKind(allocator.AllocatorChangeSync)
	IdentityChangeUpsert IdentityChangeKind = IdentityChangeKind(allocator.AllocatorChangeUpsert)
	IdentityChangeDelete IdentityChangeKind = IdentityChangeKind(allocator.AllocatorChangeDelete)
)

type IdentityChange struct {
	Kind   IdentityChangeKind
	ID     identity.NumericIdentity
	Labels labels.Labels
}

type CachingIdentityAllocator struct {
	logger *slog.Logger
}

type NoopIdentityAllocator = CachingIdentityAllocator

func NewCachingIdentityAllocator(logger *slog.Logger, _ IdentityAllocatorOwner, _ AllocatorConfig) *CachingIdentityAllocator {
	return &CachingIdentityAllocator{logger: logger}
}

func NewNoopIdentityAllocator(logger *slog.Logger) *NoopIdentityAllocator {
	return &CachingIdentityAllocator{logger: logger}
}

func (n *CachingIdentityAllocator) WaitForInitialGlobalIdentities(context.Context) error { return nil }
func (n *CachingIdentityAllocator) AllocateIdentity(context.Context, labels.Labels, bool, identity.NumericIdentity) (*identity.Identity, bool, error) {
	return identity.LookupReservedIdentity(identity.ReservedIdentityInit), false, nil
}
func (n *CachingIdentityAllocator) AllocateLocalIdentity(labels.Labels, bool, identity.NumericIdentity) (*identity.Identity, bool, error) {
	return identity.LookupReservedIdentity(identity.ReservedIdentityInit), false, nil
}
func (n *CachingIdentityAllocator) Release(context.Context, *identity.Identity, bool) (bool, error) {
	return false, nil
}
func (n *CachingIdentityAllocator) ReleaseLocalIdentities(...identity.NumericIdentity) ([]identity.NumericIdentity, error) {
	return nil, nil
}
func (n *CachingIdentityAllocator) LookupIdentity(context.Context, labels.Labels) *identity.Identity {
	return nil
}
func (n *CachingIdentityAllocator) LookupIdentityByID(context.Context, identity.NumericIdentity) *identity.Identity {
	return nil
}
func (n *CachingIdentityAllocator) GetIdentityCache() identity.IdentityMap { return identity.IdentityMap{} }
func (n *CachingIdentityAllocator) GetIdentities() IdentitiesModel         { return nil }
func (n *CachingIdentityAllocator) WithholdLocalIdentities([]identity.NumericIdentity) {}
func (n *CachingIdentityAllocator) UnwithholdLocalIdentities([]identity.NumericIdentity) {}
func (n *CachingIdentityAllocator) EnableCheckpointing()                                           {}
func (n *CachingIdentityAllocator) InitIdentityAllocator(versioned.Interface, kvstore.Client) <-chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}
func (n *CachingIdentityAllocator) RestoreLocalIdentities() (map[identity.NumericIdentity]*identity.Identity, error) {
	return map[identity.NumericIdentity]*identity.Identity{}, nil
}
func (n *CachingIdentityAllocator) ReleaseRestoredIdentities() {}
func (n *CachingIdentityAllocator) Close()                     {}
func (n *CachingIdentityAllocator) LocalIdentityChanges() stream.Observable[IdentityChange] {
	return n
}
func (n *CachingIdentityAllocator) WatchRemoteIdentities(string, uint32, kvstore.BackendOperations, bool) (allocator.RemoteIDCache, error) {
	return noopRemoteIDCache{}, nil
}
func (n *CachingIdentityAllocator) RemoveRemoteIdentities(string) {}
func (n *CachingIdentityAllocator) Observe(context.Context, func(IdentityChange), func(error)) {}

type noopRemoteIDCache struct{}

func (noopRemoteIDCache) NumEntries() int                              { return 0 }
func (noopRemoteIDCache) Synced() bool                                 { return true }
func (noopRemoteIDCache) Watch(ctx context.Context, onSync func(context.Context)) { onSync(ctx) }
