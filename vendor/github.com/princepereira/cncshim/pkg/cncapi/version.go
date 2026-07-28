package cncapi

import "fmt"

// Version represents the cncshim module version.
type Version struct {
	Major       int    `json:"major"`
	Minor       int    `json:"minor"`
	Patch       int    `json:"patch"`
	PreRelease  string `json:"prerelease,omitempty"`
	CNCApiVersion string `json:"cncApiVersion"`
}

// String returns the semver string representation.
func (v Version) String() string {
	s := fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
	if v.PreRelease != "" {
		s += "-" + v.PreRelease
	}
	return s
}

// These values are set at build time or hardcoded for the current release.
var (
	// ShimVersion is the version of the cncshim Go module.
	ShimVersion = Version{
		Major:         0,
		Minor:         1,
		Patch:         0,
		PreRelease:    "alpha",
		CNCApiVersion: "1.0",
	}
)

// GetVersion returns the current cncshim version.
func GetVersion() Version {
	return ShimVersion
}

// GetCNCApiVersion returns the CNC API version this shim is built against.
func GetCNCApiVersion() string {
	return ShimVersion.CNCApiVersion
}
