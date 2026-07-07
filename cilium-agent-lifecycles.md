# Cilium-Agent Lifecycle Sequence Diagrams

Web-sequence (Mermaid) diagrams for three core cilium-agent flows: **FQDN/DNS-proxy**,
**Endpoint lifecycle**, and **Load-balancer lifecycle**.

---

## 1. FQDN / DNS Proxy flow

How `toFQDN` policy is enforced and how name→IP mappings are learned. Source references:
[ServeDNS](pkg/fqdn/dnsproxy/proxy.go#L895), [CheckAllowed](pkg/fqdn/dnsproxy/proxy.go#L763),
[UpdateAllowed](pkg/fqdn/dnsproxy/proxy.go#L723).

```mermaid
sequenceDiagram
    autonumber
    participant Pod
    participant DP as DNS Proxy (dnsproxy)
    participant EP as Endpoint/Policy lookup
    participant Pol as Policy engine
    participant DNS as Upstream DNS (CoreDNS)
    participant Cache as FQDN cache / IPCache
    participant Maps as eBPF policy maps

    Note over Pol,DP: Policy programming (out of band)
    Pol->>DP: UpdateAllowed(epID, port, L7 DNS rules)
    DP->>DP: Compile matchName/matchPattern to regexes

    Note over Pod,Maps: DNS request path (TPROXY intercepted)
    Pod->>DP: DNS query (transparently redirected)
    DP->>EP: Identify source endpoint + original dst server
    DP->>DP: CheckAllowed(epID, dstPortProto, dstID, qname)
    alt Query NOT allowed by toFQDN policy
        DP-->>Pod: REFUSED
        DP->>Pol: NotifyOnDNSMsg(allowed=false)
    else Query allowed
        DP->>Pol: NotifyOnDNSMsg(request, allowed=true)
        DP->>DNS: Forward query
        DNS-->>DP: DNS response (A/AAAA records)
        DP->>Cache: NotifyOnDNSMsg(response) -> learn name->IP
        Cache->>Pol: Allocate identities for new IPs
        Pol->>Maps: Program IPs into policy/identity maps
        DP-->>Pod: DNS response (unmodified)
    end
    Note over Pod,Maps: Subsequent traffic to learned IPs is now allowed by datapath
```

---

## 2. Endpoint lifecycle

From CNI pod creation through identity allocation, regeneration, and deletion.
Driven via the agent REST API (`PutEndpointID` / `DeleteEndpointID`) and the
`endpoint` + `endpointmanager` cells.

```mermaid
sequenceDiagram
    autonumber
    participant CNI as CNI plugin
    participant API as Agent REST API
    participant EM as EndpointManager
    participant EP as Endpoint
    participant ID as Identity allocator
    participant IPC as IPCache
    participant Loader as Datapath loader
    participant BPF as eBPF maps/programs

    Note over CNI,BPF: Creation
    CNI->>API: PutEndpointID (CreateEndpoint)
    API->>EM: Create Endpoint object
    EM->>EP: Register, assign endpoint ID
    EP->>ID: Resolve labels -> allocate security identity
    ID-->>EP: Numeric identity
    EP->>IPC: Insert endpoint IP -> identity mapping

    Note over EP,BPF: Regeneration
    EP->>EP: Compute desired policy (ingress/egress)
    EP->>Loader: Build + compile datapath (ep_config headers)
    Loader->>BPF: Load programs, write policy/CT/endpoint maps
    EP-->>EM: State = ready / regenerated
    API-->>CNI: Success (veth/netns configured)

    Note over EP,BPF: Updates (labels / policy change)
    ID->>EP: Identity change (label update)
    EP->>EP: Trigger regeneration
    EP->>BPF: Update policy maps

    Note over CNI,BPF: Deletion
    CNI->>API: DeleteEndpointID
    API->>EM: Remove endpoint
    EM->>ID: Release identity (if last user)
    EM->>IPC: Remove IP -> identity mapping
    EM->>BPF: Unload programs, delete maps
```

---

## 3. Load-balancer lifecycle

How a Kubernetes Service becomes eBPF LB-map entries via reflectors, StateDB tables,
and the BPF reconciler. Source references:
[loadbalancer reconciler Cell](pkg/loadbalancer/reconciler/cell.go),
[BPFOps](pkg/loadbalancer/reconciler/bpf_reconciler.go), [id_allocator](pkg/loadbalancer/reconciler/id_allocator.go).

```mermaid
sequenceDiagram
    autonumber
    participant K8s as Kubernetes API
    participant Refl as LB reflectors
    participant W as Writer
    participant DB as StateDB (Service/Frontend/Backend tables)
    participant IDA as Frontend ID allocator
    participant Rec as BPF reconciler (BPFOps)
    participant Maps as LB eBPF maps
    participant Sock as Socket termination

    Note over K8s,Maps: Service create / update
    K8s->>Refl: Service + EndpointSlice events
    Refl->>W: Upsert service / frontends / backends
    W->>DB: Write desired Frontend/Backend rows
    DB->>IDA: Allocate stable frontend ID
    DB-->>Rec: Watch: changed Frontend revision
    Rec->>Maps: Program service map, backend map,<br/>rev-nat, maglev/affinity, source-ranges
    Rec-->>DB: Set reconciliation status = Done

    Note over K8s,Sock: Backend removal
    K8s->>Refl: EndpointSlice removes backend
    Refl->>W: Remove backend
    W->>DB: Delete backend row / update frontend
    DB-->>Rec: Watch: changed frontend
    Rec->>Maps: Remove backend, update service slots
    Rec->>Sock: Terminate sockets to removed backend

    Note over K8s,Maps: Service delete
    K8s->>Refl: Service deleted
    Refl->>W: Delete frontends/backends
    W->>DB: Delete rows
    DB-->>Rec: Watch: deletion
    Rec->>Maps: Prune LB-map entries
    Rec->>IDA: Release frontend ID
```

---

## How the three connect

```mermaid
flowchart LR
    subgraph ControlPlane
      FQDN[FQDN / DNS proxy]
      EPM[Endpoint manager]
      LB[Load-balancer]
    end
    K8s[Kubernetes] --> EPM
    K8s --> LB
    Pod[Pod] --> FQDN
    FQDN --> IPC[(IPCache / identities)]
    EPM --> IPC
    IPC --> BPF[(eBPF datapath maps)]
    LB --> BPF
    EPM --> BPF
```

- **FQDN** learns IPs and feeds identities into IPCache.
- **Endpoint lifecycle** allocates identities and programs per-pod policy.
- **Load-balancer** programs service→backend translation.

All three ultimately converge on the **eBPF datapath maps** that enforce traffic decisions.
