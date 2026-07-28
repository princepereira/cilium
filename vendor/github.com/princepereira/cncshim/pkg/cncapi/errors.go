package cncapi

import "fmt"

// HResult represents a Windows HRESULT value.
type HResult int32

// HResultError wraps an HRESULT with the operation that failed.
type HResultError struct {
	Code HResult
	Op   string
}

func (e *HResultError) Error() string {
	name, cause := e.Code.Describe()
	if name != "" {
		return fmt.Sprintf("cncapi: %s failed with HRESULT 0x%08X (%s): %s", e.Op, uint32(e.Code), name, cause)
	}
	return fmt.Sprintf("cncapi: %s failed with HRESULT 0x%08X", e.Op, uint32(e.Code))
}

// Common HRESULT values.
const (
	SOK             HResult = 0
	EINVALIDARG     HResult = -2147024809 // 0x80070057
	EINVALIDDATA    HResult = -2147024883 // 0x8007000D
	EALREADYEXISTS  HResult = -2147024713 // 0x800700B7
)

// knownHResults maps well-known HRESULT codes to a human-readable name and cause.
var knownHResults = map[HResult]struct {
	Name  string
	Cause string
}{
	EALREADYEXISTS: {
		Name:  "ERROR_ALREADY_EXISTS",
		Cause: "The entry already exists. If this occurs during reconciliation, the duplicate upsert can usually be ignored.",
	},
	EINVALIDARG: {
		Name:  "E_INVALIDARG",
		Cause: "An invalid argument was passed to the CNC API (e.g. a port-0 wildcard service entry that the CNC datapath cannot accept).",
	},
	EINVALIDDATA: {
		Name:  "E_INVALIDDATA",
		Cause: "The data provided is not in the expected format.",
	},
}

// Describe returns the human-readable name and cause for an HRESULT, if known.
// Returns empty strings if the HRESULT is not in the known table.
func (hr HResult) Describe() (name, cause string) {
	if info, ok := knownHResults[hr]; ok {
		return info.Name, info.Cause
	}
	return "", ""
}

// Succeeded returns true if the HRESULT indicates success.
func (hr HResult) Succeeded() bool {
	return hr >= 0
}

// checkHR returns nil if hr indicates success, otherwise returns an HResultError.
func CheckHR(hr HResult, op string) error {
	if hr.Succeeded() {
		return nil
	}
	return &HResultError{Code: hr, Op: op}
}
