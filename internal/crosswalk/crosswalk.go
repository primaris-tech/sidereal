// Package crosswalk resolves multi-framework compliance control mappings.
//
// Crosswalk data is loaded from JSON files shipped in the Helm chart.
// Each file maps (profile, nist_800_53_control) → [framework_control_ids].
// The resolver is used by the result reconciler to populate controlMappings
// on every SiderealProbeResult.
package crosswalk

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Mapping represents a single crosswalk entry.
type Mapping struct {
	Profile     string   `json:"profile"`
	NISTControl string   `json:"nist_control"`
	ControlIDs  []string `json:"control_ids"`
}

// Framework represents a loaded crosswalk file.
type Framework struct {
	FrameworkID string    `json:"framework_id"`
	Version     string    `json:"crosswalk_version"`
	Mappings    []Mapping `json:"mappings"`
}

// Resolver loads crosswalk data and resolves probe results to multi-framework control mappings.
type Resolver struct {
	mu         sync.RWMutex
	frameworks map[string]*Framework
	version    string
}

// NewResolver creates an empty resolver. Call LoadFromDir to populate.
func NewResolver() *Resolver {
	return &Resolver{
		frameworks: make(map[string]*Framework),
	}
}

// LoadFromDir loads all crosswalk JSON files from the given directory.
func (r *Resolver) LoadFromDir(dir string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return fmt.Errorf("crosswalk: failed to glob directory: %w", err)
	}

	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return fmt.Errorf("crosswalk: failed to read %s: %w", f, err)
		}

		var fw Framework
		if err := json.Unmarshal(data, &fw); err != nil {
			return fmt.Errorf("crosswalk: failed to parse %s: %w", f, err)
		}

		r.frameworks[fw.FrameworkID] = &fw
	}

	// Build a composite version string from all loaded frameworks.
	r.version = r.buildVersionString()
	return nil
}

// UpsertFramework loads or replaces a single framework in the resolver.
// It is safe to call concurrently and is idempotent on the same FrameworkID.
func (r *Resolver) UpsertFramework(fw *Framework) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.frameworks[fw.FrameworkID] = fw
	r.version = r.buildVersionString()
}

// RemoveFramework removes a framework from the resolver by ID.
// If the framework does not exist, this is a no-op.
func (r *Resolver) RemoveFramework(frameworkID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.frameworks, frameworkID)
	r.version = r.buildVersionString()
}

// LoadFramework loads a single framework from JSON data.
func (r *Resolver) LoadFramework(data []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	var fw Framework
	if err := json.Unmarshal(data, &fw); err != nil {
		return fmt.Errorf("crosswalk: failed to parse framework: %w", err)
	}

	r.frameworks[fw.FrameworkID] = &fw
	r.version = r.buildVersionString()
	return nil
}

// Resolve maps a profile and its NIST 800-53 controls to all active framework control IDs.
// Returns a map of framework_id → []control_id.
func (r *Resolver) Resolve(profile string, nistControls []string) map[string][]string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make(map[string][]string)

	// Always include the NIST controls themselves.
	if len(nistControls) > 0 {
		result["nist-800-53"] = nistControls
	}

	// Look up each framework's mappings.
	for fwID, fw := range r.frameworks {
		if fwID == "nist-800-53" {
			continue // already included above
		}

		var matched []string
		for _, mapping := range fw.Mappings {
			if mapping.Profile != profile {
				continue
			}
			for _, nist := range nistControls {
				if mapping.NISTControl == nist {
					matched = append(matched, mapping.ControlIDs...)
				}
			}
		}
		if len(matched) > 0 {
			result[fwID] = deduplicate(matched)
		}
	}

	return result
}

// Version returns the composite crosswalk version string.
func (r *Resolver) Version() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.version
}

// FrameworkCount returns the number of loaded frameworks.
func (r *Resolver) FrameworkCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.frameworks)
}

func (r *Resolver) buildVersionString() string {
	if len(r.frameworks) == 0 {
		return ""
	}
	s := ""
	for id, fw := range r.frameworks {
		if s != "" {
			s += ";"
		}
		s += id + ":" + fw.Version
	}
	return s
}

func deduplicate(s []string) []string {
	seen := make(map[string]bool, len(s))
	result := make([]string, 0, len(s))
	for _, v := range s {
		if !seen[v] {
			seen[v] = true
			result = append(result, v)
		}
	}
	return result
}
