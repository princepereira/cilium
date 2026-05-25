// Package cncapi implements the CNCApi interface using windows.LazyDLL
// to load cncapi.dll at runtime. No CGo dependency is required.
//
// This package only supports Windows amd64.
package cncapi

import (
	"fmt"
	"net/netip"
	"runtime"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	dll  *windows.LazyDLL
	once sync.Once
)

func loadDLL() {
	dll = windows.NewLazyDLL("cncapi.dll")
}

func getDLL() *windows.LazyDLL {
	once.Do(loadDLL)
	return dll
}

func proc(name string) *windows.LazyProc {
	return getDLL().NewProc(name)
}

// Client implements CNCApi using syscall to call cncapi.dll.
type Client struct {
	mu          sync.Mutex
	initialized bool
}

var _ CNCApi = (*Client)(nil)

// New creates a new Client and calls CncInitialize.
// The caller must be running with Administrator (elevated) privileges and the
// CNC kernel components (eBPF runtime, bpf_sock.sys) must be installed.
func New() (*Client, error) {
	if err := checkElevated(); err != nil {
		return nil, fmt.Errorf("cncapi: %w", err)
	}
	c := &Client{}
	r, _, _ := proc("CncInitialize").Call()
	if err := CheckHR(HResult(int32(r)), "CncInitialize"); err != nil {
		return nil, fmt.Errorf("%w\n%s", err, diagnoseInitFailure())
	}
	c.initialized = true
	return c, nil
}

// checkElevated verifies the current process is running with Administrator privileges.
func checkElevated() error {
	var token windows.Token
	process := windows.CurrentProcess()
	if err := windows.OpenProcessToken(process, windows.TOKEN_QUERY, &token); err != nil {
		return fmt.Errorf("failed to open process token: %w", err)
	}
	defer token.Close()

	if !token.IsElevated() {
		return fmt.Errorf("CncInitialize requires elevated (Administrator) privileges. " +
			"Please run the process from an Administrator command prompt")
	}
	return nil
}

// diagnoseInitFailure checks common prerequisites for CncInitialize and returns
// a diagnostic message describing what may be missing.
func diagnoseInitFailure() string {
	var issues []string

	// Check if wcnagent is already loaded by HNS (most common cause on K8s nodes)
	if isWcnAgentLoaded() {
		return "Hint: wcnagent.dll is already loaded by HNS (CiliumOnWindows is enabled). " +
			"CncInitialize can only be called by one process at a time. " +
			"Disable wcnagent first:\n" +
			"  Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\hns\\State' -Name CiliumOnWindows -Value 0\n" +
			"  Restart-Service hns -Force"
	}

	// Check ebpfcore service
	if !isServiceRunning("ebpfcore") {
		issues = append(issues, "- 'ebpfcore' service is not running (eBPF for Windows runtime required)")
	}
	// Check netebpfext service
	if !isServiceRunning("netebpfext") {
		issues = append(issues, "- 'netebpfext' service is not running (eBPF network extension required)")
	}
	// Check HNS service
	if !isServiceRunning("hns") {
		issues = append(issues, "- 'hns' (Host Network Service) is not running")
	}

	if len(issues) == 0 {
		return "Hint: Ensure the CNC BPF programs (bpf_sock.sys) are loaded into the eBPF framework " +
			"and ebpfapi.dll is present in System32."
	}

	msg := "Hint: CncInitialize failed. The following prerequisites are not met:\n"
	for _, issue := range issues {
		msg += issue + "\n"
	}
	msg += "Install eBPF for Windows and load the CNC BPF programs before calling CncInitialize."
	return msg
}

// isWcnAgentLoaded checks if wcnagent.dll is loaded by any process (indicating HNS owns CNC).
func isWcnAgentLoaded() bool {
	// Query registry to check if CiliumOnWindows is enabled
	keyPath, _ := windows.UTF16PtrFromString(`SYSTEM\CurrentControlSet\Services\hns\State`)
	var key windows.Handle
	if err := windows.RegOpenKeyEx(windows.HKEY_LOCAL_MACHINE, keyPath,
		0, windows.KEY_READ, &key); err != nil {
		return false
	}
	defer windows.RegCloseKey(key)

	valName, _ := windows.UTF16PtrFromString("CiliumOnWindows")
	var valType uint32
	var buf [4]byte
	bufLen := uint32(len(buf))
	if err := windows.RegQueryValueEx(key, valName, nil, &valType, &buf[0], &bufLen); err != nil {
		return false
	}
	// DWORD value: check if non-zero
	dword := uint32(buf[0]) | uint32(buf[1])<<8 | uint32(buf[2])<<16 | uint32(buf[3])<<24
	return dword != 0
}

// isServiceRunning queries the Windows Service Control Manager to check if a service is running.
func isServiceRunning(name string) bool {
	m, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return false
	}
	defer windows.CloseServiceHandle(m)

	svcName, _ := windows.UTF16PtrFromString(name)
	s, err := windows.OpenService(m, svcName, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return false
	}
	defer windows.CloseServiceHandle(s)

	var status windows.SERVICE_STATUS
	if err := windows.QueryServiceStatus(s, &status); err != nil {
		return false
	}
	return status.CurrentState == windows.SERVICE_RUNNING
}

// Close calls CncUninitialize.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.initialized {
		return nil
	}
	proc("CncUninitialize").Call()
	c.initialized = false
	return nil
}

func (c *Client) checkInit() error {
	if !c.initialized {
		return fmt.Errorf("cncapi: client not initialized")
	}
	return nil
}

// --- Node Configuration ---

func (c *Client) GetNodeConfiguration() (*NodeConfigInfo, error) {
	if err := c.checkInit(); err != nil {
		return nil, err
	}
	var ptr uintptr
	r, _, _ := proc("CncGetNodeConfiguration").Call(uintptr(unsafe.Pointer(&ptr)))
	if err := CheckHR(HResult(int32(r)), "CncGetNodeConfiguration"); err != nil {
		return nil, err
	}
	defer proc("CncFreeNodeConfigurationInfo").Call(ptr)

	raw := (*abiNodeConfigInfo)(unsafe.Pointer(ptr)) //nolint:govet // ptr is DLL-allocated
	result := &NodeConfigInfo{
		DirectRoutingInterface:   abiInterfaceToGo(raw.DirectRoutingInterface),
		NodePortServicePortRange: PortRange{MinPort: raw.NodePortServicePortRange.MinPort, MaxPort: raw.NodePortServicePortRange.MaxPort},
		NodePortNATPortRange:     PortRange{MinPort: raw.NodePortNATPortRange.MinPort, MaxPort: raw.NodePortNATPortRange.MaxPort},
		HashSeeds:                HashSeeds{IPv4: raw.HashSeeds.HashSeedIPv4, IPv6: raw.HashSeeds.HashSeedIPv6},
	}
	if raw.NativeInterfacesCount > 0 && raw.NativeInterfaces != 0 {
		ifaces := unsafe.Slice((*abiInterfaceInfo)(unsafe.Pointer(raw.NativeInterfaces)), raw.NativeInterfacesCount) //nolint:govet
		result.NativeInterfaces = make([]InterfaceInfo, len(ifaces))
		for i, iface := range ifaces {
			result.NativeInterfaces[i] = abiInterfaceInfoToGo(iface)
		}
	}
	runtime.KeepAlive(ptr)
	return result, nil
}

func (c *Client) AddOrUpdateNodeConfiguration(config *NodeConfigInfo) error {
	if err := c.checkInit(); err != nil {
		return err
	}
	nativeIfaces := make([]abiInterfaceInfo, len(config.NativeInterfaces))
	for i, iface := range config.NativeInterfaces {
		nativeIfaces[i] = interfaceInfoToABI(iface)
	}
	raw := abiNodeConfigInfo{
		NativeInterfacesCount:    uintptr(len(nativeIfaces)),
		DirectRoutingInterface:   interfaceToABI(config.DirectRoutingInterface),
		NodePortServicePortRange: abiPortRange{MinPort: config.NodePortServicePortRange.MinPort, MaxPort: config.NodePortServicePortRange.MaxPort},
		NodePortNATPortRange:     abiPortRange{MinPort: config.NodePortNATPortRange.MinPort, MaxPort: config.NodePortNATPortRange.MaxPort},
		HashSeeds:                abiHashSeeds{HashSeedIPv4: config.HashSeeds.IPv4, HashSeedIPv6: config.HashSeeds.IPv6},
	}
	if len(nativeIfaces) > 0 {
		raw.NativeInterfaces = uintptr(unsafe.Pointer(&nativeIfaces[0]))
	}
	r, _, _ := proc("CncAddOrUpdateNodeConfiguration").Call(uintptr(unsafe.Pointer(&raw)))
	runtime.KeepAlive(nativeIfaces)
	runtime.KeepAlive(raw)
	return CheckHR(HResult(int32(r)), "CncAddOrUpdateNodeConfiguration")
}

func (c *Client) UpdateNodeConfigurationHashSeeds(seeds *HashSeeds) error {
	if err := c.checkInit(); err != nil {
		return err
	}
	raw := abiHashSeeds{HashSeedIPv4: seeds.IPv4, HashSeedIPv6: seeds.IPv6}
	r, _, _ := proc("CncUpdateNodeConfigurationHashSeeds").Call(uintptr(unsafe.Pointer(&raw)))
	runtime.KeepAlive(raw)
	return CheckHR(HResult(int32(r)), "CncUpdateNodeConfigurationHashSeeds")
}

func (c *Client) SetNodeConfigurationInfraInterface(info *NodeInfraNicInfo) error {
	if err := c.checkInit(); err != nil {
		return err
	}
	raw := nodeInfraNicInfoToABI(info)
	r, _, _ := proc("CncSetNodeConfigurationInfraInterface").Call(uintptr(unsafe.Pointer(&raw)))
	runtime.KeepAlive(raw)
	return CheckHR(HResult(int32(r)), "CncSetNodeConfigurationInfraInterface")
}

func (c *Client) GetNodeConfigurationInfraInterface() (*NodeInfraNicInfo, error) {
	if err := c.checkInit(); err != nil {
		return nil, err
	}
	var raw abiNodeInfraNicInfo
	r, _, _ := proc("CncGetNodeConfigurationInfraInterface").Call(uintptr(unsafe.Pointer(&raw)))
	if err := CheckHR(HResult(int32(r)), "CncGetNodeConfigurationInfraInterface"); err != nil {
		return nil, err
	}
	return abiNodeInfraNicInfoToGo(raw), nil
}

// --- Observability ---

func (c *Client) SetTraceConfiguration(flags NotifyEnableFlags, options *TraceOptions) error {
	if err := c.checkInit(); err != nil {
		return err
	}
	var optPtr uintptr
	var rawOpts abiTraceOptions
	if options != nil {
		rawOpts = traceOptionsToABI(options)
		optPtr = uintptr(unsafe.Pointer(&rawOpts))
	}
	r, _, _ := proc("CncSetTraceConfiguration").Call(uintptr(flags), optPtr)
	runtime.KeepAlive(rawOpts)
	return CheckHR(HResult(int32(r)), "CncSetTraceConfiguration")
}

func (c *Client) GetTraceConfiguration() (NotifyEnableFlags, *TraceOptions, error) {
	if err := c.checkInit(); err != nil {
		return 0, nil, err
	}
	var flags uint32
	var rawOpts abiTraceOptions
	r, _, _ := proc("CncGetTraceConfiguration").Call(
		uintptr(unsafe.Pointer(&flags)),
		uintptr(unsafe.Pointer(&rawOpts)),
	)
	if err := CheckHR(HResult(int32(r)), "CncGetTraceConfiguration"); err != nil {
		return 0, nil, err
	}
	return NotifyEnableFlags(flags), abiTraceOptionsToGo(rawOpts), nil
}

// --- Connection Tracking ---

func (c *Client) SetCtConfiguration(config *CTConfigInfo) error {
	if err := c.checkInit(); err != nil {
		return err
	}
	var ptr uintptr
	var raw abiCTConfigInfo
	if config != nil {
		raw = ctConfigInfoToABI(config)
		ptr = uintptr(unsafe.Pointer(&raw))
	}
	r, _, _ := proc("CncSetCtConfiguration").Call(ptr)
	runtime.KeepAlive(raw)
	return CheckHR(HResult(int32(r)), "CncSetCtConfiguration")
}

func (c *Client) GetCtConfiguration() (*CTConfigInfo, error) {
	if err := c.checkInit(); err != nil {
		return nil, err
	}
	var raw abiCTConfigInfo
	r, _, _ := proc("CncGetCtConfiguration").Call(uintptr(unsafe.Pointer(&raw)))
	if err := CheckHR(HResult(int32(r)), "CncGetCtConfiguration"); err != nil {
		return nil, err
	}
	return abiCTConfigInfoToGo(raw), nil
}

// --- Load Balancer ---

func (c *Client) CreateLoadBalancerBackends(backends []BackendInfo) error {
	if err := c.checkInit(); err != nil {
		return err
	}
	rawBackends := make([]abiBackendInfo, len(backends))
	for i, b := range backends {
		rawBackends[i] = backendInfoToABI(b)
	}
	var ptr uintptr
	if len(rawBackends) > 0 {
		ptr = uintptr(unsafe.Pointer(&rawBackends[0]))
	}
	r, _, _ := proc("CncCreateLoadBalancerBackends").Call(uintptr(len(rawBackends)), ptr)
	runtime.KeepAlive(rawBackends)
	return CheckHR(HResult(int32(r)), "CncCreateLoadBalancerBackends")
}

func (c *Client) CreateLoadBalancerService(serviceID uint16, info *LoadBalancerInfo) error {
	if err := c.checkInit(); err != nil {
		return err
	}
	raw := loadBalancerInfoToABI(info)
	r, _, _ := proc("CncCreateLoadBalancerService").Call(uintptr(serviceID), uintptr(unsafe.Pointer(&raw)))
	runtime.KeepAlive(raw)
	return CheckHR(HResult(int32(r)), "CncCreateLoadBalancerService")
}

func (c *Client) UpdateLoadBalancerServiceBackends(serviceID uint16, info *LoadBalancerInfo, newBackends []BackendInfo, oldBackends []BackendInfo) error {
	if err := c.checkInit(); err != nil {
		return err
	}
	rawInfo := loadBalancerInfoToABI(info)
	newRaw := make([]abiBackendInfo, len(newBackends))
	for i, b := range newBackends {
		newRaw[i] = backendInfoToABI(b)
	}
	oldRaw := make([]abiBackendInfo, len(oldBackends))
	for i, b := range oldBackends {
		oldRaw[i] = backendInfoToABI(b)
	}
	var newPtr, oldPtr uintptr
	if len(newRaw) > 0 {
		newPtr = uintptr(unsafe.Pointer(&newRaw[0]))
	}
	if len(oldRaw) > 0 {
		oldPtr = uintptr(unsafe.Pointer(&oldRaw[0]))
	}
	r, _, _ := proc("CncUpdateLoadBalancerServiceBackends").Call(
		uintptr(serviceID),
		uintptr(unsafe.Pointer(&rawInfo)),
		uintptr(len(newRaw)),
		newPtr,
		uintptr(len(oldRaw)),
		oldPtr,
	)
	runtime.KeepAlive(rawInfo)
	runtime.KeepAlive(newRaw)
	runtime.KeepAlive(oldRaw)
	return CheckHR(HResult(int32(r)), "CncUpdateLoadBalancerServiceBackends")
}

func (c *Client) GetLoadBalancerService(frontend *FrontendInfo) (*LoadBalancerInfo, error) {
	if err := c.checkInit(); err != nil {
		return nil, err
	}
	rawFe := frontendInfoToABI(frontend)
	var rawInfo abiLoadBalancerInfo
	r, _, _ := proc("CncGetLoadBalancerService").Call(
		uintptr(unsafe.Pointer(&rawFe)),
		uintptr(unsafe.Pointer(&rawInfo)),
	)
	runtime.KeepAlive(rawFe)
	if err := CheckHR(HResult(int32(r)), "CncGetLoadBalancerService"); err != nil {
		return nil, err
	}
	return abiLoadBalancerInfoToGo(rawInfo), nil
}

func (c *Client) DeleteLoadBalancerService(serviceID uint16, info *LoadBalancerInfo) error {
	if err := c.checkInit(); err != nil {
		return err
	}
	raw := loadBalancerInfoToABI(info)
	r, _, _ := proc("CncDeleteLoadBalancerService").Call(uintptr(serviceID), uintptr(unsafe.Pointer(&raw)))
	runtime.KeepAlive(raw)
	return CheckHR(HResult(int32(r)), "CncDeleteLoadBalancerService")
}

func (c *Client) DeleteLoadBalancerBackends(addressFamily uint16, backendIDs []uint32) error {
	if err := c.checkInit(); err != nil {
		return err
	}
	var ptr uintptr
	if len(backendIDs) > 0 {
		ptr = uintptr(unsafe.Pointer(&backendIDs[0]))
	}
	r, _, _ := proc("CncDeleteLoadBalancerBackends").Call(
		uintptr(addressFamily),
		uintptr(len(backendIDs)),
		ptr,
	)
	runtime.KeepAlive(backendIDs)
	return CheckHR(HResult(int32(r)), "CncDeleteLoadBalancerBackends")
}

func (c *Client) GetLoadBalancerBackends(addressFamily uint16, backendIDs []uint32) ([]BackendQueryResult, error) {
	if err := c.checkInit(); err != nil {
		return nil, err
	}
	if len(backendIDs) == 0 {
		return nil, nil
	}
	results := make([]abiBackendQueryResult, len(backendIDs))
	r, _, _ := proc("CncGetLoadBalancerBackends").Call(
		uintptr(addressFamily),
		uintptr(len(backendIDs)),
		uintptr(unsafe.Pointer(&backendIDs[0])),
		uintptr(unsafe.Pointer(&results[0])),
	)
	runtime.KeepAlive(backendIDs)
	if err := CheckHR(HResult(int32(r)), "CncGetLoadBalancerBackends"); err != nil {
		return nil, err
	}
	goResults := make([]BackendQueryResult, len(results))
	for i, res := range results {
		goResults[i] = BackendQueryResult{
			Info:   abiBackendInfoToGo(res.Info),
			Result: HResult(res.Result),
		}
	}
	return goResults, nil
}

// --- Endpoint ---

func (c *Client) AddOrUpdateEndpoint(newEndpoint *EndpointInfo, oldEndpoint *EndpointInfo, disposition CreationDisposition) error {
	if err := c.checkInit(); err != nil {
		return err
	}
	rawNew := endpointInfoToABI(newEndpoint)
	var oldPtr uintptr
	var rawOld abiEndpointInfo
	if oldEndpoint != nil {
		rawOld = endpointInfoToABI(oldEndpoint)
		oldPtr = uintptr(unsafe.Pointer(&rawOld))
	}
	r, _, _ := proc("CncAddOrUpdateEndpoint").Call(
		uintptr(unsafe.Pointer(&rawNew)),
		oldPtr,
		uintptr(disposition),
	)
	runtime.KeepAlive(rawNew)
	runtime.KeepAlive(rawOld)
	return CheckHR(HResult(int32(r)), "CncAddOrUpdateEndpoint")
}

func (c *Client) DeleteEndpoint(address *EndpointAddress) error {
	if err := c.checkInit(); err != nil {
		return err
	}
	raw := endpointAddressToABI(address)
	r, _, _ := proc("CncDeleteEndpoint").Call(uintptr(unsafe.Pointer(&raw)))
	runtime.KeepAlive(raw)
	return CheckHR(HResult(int32(r)), "CncDeleteEndpoint")
}

func (c *Client) GetEndpoint(address *EndpointAddress) (*EndpointInfo, error) {
	if err := c.checkInit(); err != nil {
		return nil, err
	}
	rawAddr := endpointAddressToABI(address)
	var rawEp abiEndpointInfo
	r, _, _ := proc("CncGetEndpoint").Call(
		uintptr(unsafe.Pointer(&rawAddr)),
		uintptr(unsafe.Pointer(&rawEp)),
	)
	runtime.KeepAlive(rawAddr)
	if err := CheckHR(HResult(int32(r)), "CncGetEndpoint"); err != nil {
		return nil, err
	}
	return abiEndpointInfoToGo(rawEp), nil
}

// --- Policy ---

func (c *Client) GetEndpointPolicy(ifindex uint32, key *PolicyKey) (*Policy, error) {
	if err := c.checkInit(); err != nil {
		return nil, err
	}
	rawKey := policyKeyToABI(key)
	var rawPolicy abiPolicy
	r, _, _ := proc("CncGetEndpointPolicy").Call(
		uintptr(ifindex),
		uintptr(unsafe.Pointer(&rawKey)),
		uintptr(unsafe.Pointer(&rawPolicy)),
	)
	runtime.KeepAlive(rawKey)
	if err := CheckHR(HResult(int32(r)), "CncGetEndpointPolicy"); err != nil {
		return nil, err
	}
	result := abiPolicyToGo(rawPolicy)
	return &result, nil
}

func (c *Client) AddOrUpdateEndpointPolicies(ifindex uint32, policies []Policy) error {
	if err := c.checkInit(); err != nil {
		return err
	}
	rawPolicies := make([]abiPolicy, len(policies))
	for i, p := range policies {
		rawPolicies[i] = policyToABI(p)
	}
	var ptr uintptr
	if len(rawPolicies) > 0 {
		ptr = uintptr(unsafe.Pointer(&rawPolicies[0]))
	}
	r, _, _ := proc("CncAddOrUpdateEndpointPolicies").Call(
		uintptr(ifindex),
		uintptr(len(rawPolicies)),
		ptr,
	)
	runtime.KeepAlive(rawPolicies)
	return CheckHR(HResult(int32(r)), "CncAddOrUpdateEndpointPolicies")
}

func (c *Client) DeleteEndpointPolicies(ifindex uint32, keys []PolicyKey) error {
	if err := c.checkInit(); err != nil {
		return err
	}
	rawKeys := make([]abiPolicyKey, len(keys))
	for i, k := range keys {
		rawKeys[i] = policyKeyToABI(&k)
	}
	var ptr uintptr
	if len(rawKeys) > 0 {
		ptr = uintptr(unsafe.Pointer(&rawKeys[0]))
	}
	r, _, _ := proc("CncDeleteEndpointPolicies").Call(
		uintptr(ifindex),
		uintptr(len(rawKeys)),
		ptr,
	)
	runtime.KeepAlive(rawKeys)
	return CheckHR(HResult(int32(r)), "CncDeleteEndpointPolicies")
}

// --- Identity ---

func (c *Client) SetIdentity(subnet netip.Prefix, identity uint32) error {
	if err := c.checkInit(); err != nil {
		return err
	}
	raw := prefixToABI(subnet)
	r, _, _ := proc("CncSetIdentity").Call(uintptr(unsafe.Pointer(&raw)), uintptr(identity))
	runtime.KeepAlive(raw)
	return CheckHR(HResult(int32(r)), "CncSetIdentity")
}

func (c *Client) GetIdentity(subnet netip.Prefix) (uint32, error) {
	if err := c.checkInit(); err != nil {
		return 0, err
	}
	raw := prefixToABI(subnet)
	var identity uint32
	r, _, _ := proc("CncGetIdentity").Call(
		uintptr(unsafe.Pointer(&raw)),
		uintptr(unsafe.Pointer(&identity)),
	)
	runtime.KeepAlive(raw)
	if err := CheckHR(HResult(int32(r)), "CncGetIdentity"); err != nil {
		return 0, err
	}
	return identity, nil
}

func (c *Client) DeleteIdentity(subnet netip.Prefix) error {
	if err := c.checkInit(); err != nil {
		return err
	}
	raw := prefixToABI(subnet)
	r, _, _ := proc("CncDeleteIdentity").Call(uintptr(unsafe.Pointer(&raw)))
	runtime.KeepAlive(raw)
	return CheckHR(HResult(int32(r)), "CncDeleteIdentity")
}

// --- Neighbor ---

func (c *Client) AddOrUpdateNeighbor(neighbor *NeighborInfo) error {
	if err := c.checkInit(); err != nil {
		return err
	}
	raw := neighborInfoToABI(neighbor)
	r, _, _ := proc("CncAddOrUpdateNeighbor").Call(uintptr(unsafe.Pointer(&raw)))
	runtime.KeepAlive(raw)
	return CheckHR(HResult(int32(r)), "CncAddOrUpdateNeighbor")
}

func (c *Client) DeleteNeighbor(ip netip.Addr) error {
	if err := c.checkInit(); err != nil {
		return err
	}
	raw := addrToABI(ip)
	r, _, _ := proc("CncDeleteNeighbor").Call(uintptr(unsafe.Pointer(&raw)))
	runtime.KeepAlive(raw)
	return CheckHR(HResult(int32(r)), "CncDeleteNeighbor")
}

func (c *Client) GetNeighbors() ([]NeighborInfo, error) {
	if err := c.checkInit(); err != nil {
		return nil, err
	}
	var count uintptr
	var ptr uintptr
	r, _, _ := proc("CncGetNeighbors").Call(
		uintptr(unsafe.Pointer(&count)),
		uintptr(unsafe.Pointer(&ptr)),
	)
	if err := CheckHR(HResult(int32(r)), "CncGetNeighbors"); err != nil {
		return nil, err
	}
	if count == 0 || ptr == 0 {
		return nil, nil
	}
	defer proc("CncFreeNeighborInfos").Call(ptr)

	rawNeighbors := unsafe.Slice((*abiNeighborInfo)(unsafe.Pointer(ptr)), count) //nolint:govet
	result := make([]NeighborInfo, count)
	for i, n := range rawNeighbors {
		result[i] = abiNeighborInfoToGo(n)
	}
	runtime.KeepAlive(ptr)
	return result, nil
}

// --- Internet ---

func (c *Client) AddInternetExcludedSubnets(subnets []netip.Prefix) error {
	if err := c.checkInit(); err != nil {
		return err
	}
	raw := make([]abiIPSubnet, len(subnets))
	for i, s := range subnets {
		raw[i] = prefixToABI(s)
	}
	var ptr uintptr
	if len(raw) > 0 {
		ptr = uintptr(unsafe.Pointer(&raw[0]))
	}
	r, _, _ := proc("CncAddInternetExcludedSubnets").Call(uintptr(len(raw)), ptr)
	runtime.KeepAlive(raw)
	return CheckHR(HResult(int32(r)), "CncAddInternetExcludedSubnets")
}

func (c *Client) DeleteInternetExcludedSubnets(subnets []netip.Prefix) error {
	if err := c.checkInit(); err != nil {
		return err
	}
	raw := make([]abiIPSubnet, len(subnets))
	for i, s := range subnets {
		raw[i] = prefixToABI(s)
	}
	var ptr uintptr
	if len(raw) > 0 {
		ptr = uintptr(unsafe.Pointer(&raw[0]))
	}
	r, _, _ := proc("CncDeleteInternetExcludedSubnets").Call(uintptr(len(raw)), ptr)
	runtime.KeepAlive(raw)
	return CheckHR(HResult(int32(r)), "CncDeleteInternetExcludedSubnets")
}

// --- SNAT ---

func (c *Client) AddSnatExcludedSubnets(subnets []netip.Prefix) error {
	if err := c.checkInit(); err != nil {
		return err
	}
	raw := make([]abiIPSubnet, len(subnets))
	for i, s := range subnets {
		raw[i] = prefixToABI(s)
	}
	var ptr uintptr
	if len(raw) > 0 {
		ptr = uintptr(unsafe.Pointer(&raw[0]))
	}
	r, _, _ := proc("CncAddSnatExcludedSubnets").Call(uintptr(len(raw)), ptr)
	runtime.KeepAlive(raw)
	return CheckHR(HResult(int32(r)), "CncAddSnatExcludedSubnets")
}

func (c *Client) DeleteSnatExcludedSubnets(subnets []netip.Prefix) error {
	if err := c.checkInit(); err != nil {
		return err
	}
	raw := make([]abiIPSubnet, len(subnets))
	for i, s := range subnets {
		raw[i] = prefixToABI(s)
	}
	var ptr uintptr
	if len(raw) > 0 {
		ptr = uintptr(unsafe.Pointer(&raw[0]))
	}
	r, _, _ := proc("CncDeleteSnatExcludedSubnets").Call(uintptr(len(raw)), ptr)
	runtime.KeepAlive(raw)
	return CheckHR(HResult(int32(r)), "CncDeleteSnatExcludedSubnets")
}

// --- Garbage Collection ---

func (c *Client) SetGarbageCollectionConfiguration(config *GarbageCollectionConfig) error {
	if err := c.checkInit(); err != nil {
		return err
	}
	var raw abiGarbageCollectionConfig
	raw.CTGCMode = int32(config.Mode)
	switch config.Mode {
	case CTGCModeAdaptive:
		adaptive := abiGCAdaptiveConfig{
			StartingTimeIntervalSeconds: config.Adaptive.StartingTimeIntervalSeconds,
			MinTimeIntervalSeconds:      config.Adaptive.MinTimeIntervalSeconds,
			MaxTimeIntervalSeconds:      config.Adaptive.MaxTimeIntervalSeconds,
		}
		*(*abiGCAdaptiveConfig)(unsafe.Pointer(&raw.Union)) = adaptive
	case CTGCModeStatic:
		static := abiGCStaticConfig{
			TimeIntervalSeconds: config.Static.TimeIntervalSeconds,
		}
		*(*abiGCStaticConfig)(unsafe.Pointer(&raw.Union)) = static
	}
	r, _, _ := proc("CncSetGarbageCollectionConfiguration").Call(uintptr(unsafe.Pointer(&raw)))
	runtime.KeepAlive(raw)
	return CheckHR(HResult(int32(r)), "CncSetGarbageCollectionConfiguration")
}

// --- Test Configuration ---

func (c *Client) SetTestConfiguration(config *TestConfigInfo) {
	if c.checkInit() != nil {
		return
	}
	raw := abiTestConfigInfo{Flags: uint32(config.Flags)}
	proc("CncSetTestConfiguration").Call(uintptr(unsafe.Pointer(&raw)))
	runtime.KeepAlive(raw)
}

func (c *Client) GetTestConfiguration() (*TestConfigInfo, error) {
	if err := c.checkInit(); err != nil {
		return nil, err
	}
	var raw abiTestConfigInfo
	r, _, _ := proc("CncGetTestConfiguration").Call(uintptr(unsafe.Pointer(&raw)))
	if err := CheckHR(HResult(int32(r)), "CncGetTestConfiguration"); err != nil {
		return nil, err
	}
	return &TestConfigInfo{Flags: TestConfigFlags(raw.Flags)}, nil
}
