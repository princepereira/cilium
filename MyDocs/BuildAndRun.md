**Build**

```
go mod tidy
go mod vendor
go build -mod=vendor -o bin\cilium-agent.exe .\daemon
```

**Run**

```
kubectl create serviceaccount cilium -n kube-system

kubectl apply -f C:\Users\ppereira\Projects\Go\cilium-windows\MyDocs\cilium-clusterrole.yaml

kubectl create clusterrolebinding cilium-nodes --clusterrole=cilium --group=system:nodes

cd C:\Users\ppereira\Projects\Go\cilium-windows

kubectl apply -f pkg\k8s\apis\cilium.io\client\crds\v2\ -f pkg\k8s\apis\cilium.io\client\crds\v2alpha1\

kubectl get crd | Select-String "cilium"


## Set Pod CIDR ##

'{"spec":{"ipam":{"podCIDRs":["10.244.0.0/16"]}}}' | Set-Content -NoNewline patch.json
kubectl patch ciliumnode aksnpcil000001 --type merge --patch-file patch.json

.\cilium-agent.exe --k8s-kubeconfig-path C:\k\config --state-dir C:\cilium\state --socket-path C:\cilium\state\cilium.sock --k8s-namespace kube-system --enable-ipv6=false --enable-l7-proxy=false
```