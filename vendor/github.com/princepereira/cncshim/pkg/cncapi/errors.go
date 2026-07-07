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
	return fmt.Sprintf("cncapi: %s failed with HRESULT 0x%08X", e.Op, uint32(e.Code))
}

// Common HRESULT values.
const (
	SOK          HResult = 0
	EINVALIDARG  HResult = -2147024809 // 0x80070057
	EINVALIDDATA HResult = -2147024883 // 0x8007000D
)

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
