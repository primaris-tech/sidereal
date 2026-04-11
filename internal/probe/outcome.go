// Package probe provides the shared framework for all Go-based probe runners.
package probe

// Result represents the output of a probe execution.
type Result struct {
	// Outcome is one of the 12 standard probe outcomes.
	Outcome string `json:"outcome"`

	// Detail is a human-readable description of the result.
	Detail string `json:"detail"`

	// DurationMs is the probe execution duration in milliseconds.
	DurationMs int64 `json:"durationMs"`
}
