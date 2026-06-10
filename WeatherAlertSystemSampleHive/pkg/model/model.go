// SPDX-License-Identifier: Apache-2.0

// Package model defines shared data types used across all cells.
package model

import "time"

// WeatherReading is the core data unit produced by sensors and processed by alerts.
type WeatherReading struct {
	Temperature float64   `json:"temperature"`
	Humidity    float64   `json:"humidity"`
	WindSpeed   float64   `json:"wind_speed"`
	Location    string    `json:"location"`
	Timestamp   time.Time `json:"timestamp"`
}

// Alert represents a triggered weather alert.
type Alert struct {
	Severity string         // "WARNING", "CRITICAL"
	Message  string
	Reading  WeatherReading
}
