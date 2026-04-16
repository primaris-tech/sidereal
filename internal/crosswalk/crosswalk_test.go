package crosswalk

import (
	"testing"
)

const testCMMCCrosswalk = `{
	"framework_id": "cmmc",
	"crosswalk_version": "1.0.0",
	"mappings": [
		{"profile": "rbac", "nist_control": "AC-3", "control_ids": ["AC.L2-3.1.1"]},
		{"profile": "rbac", "nist_control": "AC-6", "control_ids": ["AC.L2-3.1.5"]},
		{"profile": "netpol", "nist_control": "SC-7", "control_ids": ["SC.L2-3.13.1", "SC.L2-3.13.6"]},
		{"profile": "admission", "nist_control": "CM-7", "control_ids": ["CM.L2-3.4.7"]}
	]
}`

const testSTIGCrosswalk = `{
	"framework_id": "kubernetes-stig",
	"crosswalk_version": "1.0.0",
	"mappings": [
		{"profile": "rbac", "nist_control": "AC-3", "control_ids": ["V-242435"]},
		{"profile": "admission", "nist_control": "CM-7", "control_ids": ["V-242437"]}
	]
}`

func setupResolver(t *testing.T) *Resolver {
	t.Helper()
	r := NewResolver()
	if err := r.LoadFramework([]byte(testCMMCCrosswalk)); err != nil {
		t.Fatalf("failed to load CMMC crosswalk: %v", err)
	}
	if err := r.LoadFramework([]byte(testSTIGCrosswalk)); err != nil {
		t.Fatalf("failed to load STIG crosswalk: %v", err)
	}
	return r
}

func TestResolve_SingleFramework(t *testing.T) {
	r := NewResolver()
	_ = r.LoadFramework([]byte(testCMMCCrosswalk))

	result := r.Resolve("rbac", []string{"AC-3", "AC-6"})

	if nist := result["nist-800-53"]; len(nist) != 2 {
		t.Errorf("expected 2 NIST controls, got %v", nist)
	}

	cmmc := result["cmmc"]
	if len(cmmc) != 2 {
		t.Errorf("expected 2 CMMC controls, got %v", cmmc)
	}
}

func TestResolve_MultiFramework(t *testing.T) {
	r := setupResolver(t)

	result := r.Resolve("rbac", []string{"AC-3"})

	if nist := result["nist-800-53"]; len(nist) != 1 || nist[0] != "AC-3" {
		t.Errorf("expected [AC-3], got %v", nist)
	}

	cmmc := result["cmmc"]
	if len(cmmc) != 1 || cmmc[0] != "AC.L2-3.1.1" {
		t.Errorf("expected [AC.L2-3.1.1], got %v", cmmc)
	}

	stig := result["kubernetes-stig"]
	if len(stig) != 1 || stig[0] != "V-242435" {
		t.Errorf("expected [V-242435], got %v", stig)
	}
}

func TestResolve_NoMatch(t *testing.T) {
	r := setupResolver(t)

	result := r.Resolve("rbac", []string{"SI-4"})

	if nist := result["nist-800-53"]; len(nist) != 1 {
		t.Errorf("expected NIST to still be present, got %v", nist)
	}

	if _, ok := result["cmmc"]; ok {
		t.Error("should not have CMMC mapping for SI-4 on rbac probe")
	}
}

func TestResolve_ProbeTypeFiltering(t *testing.T) {
	r := setupResolver(t)

	// SC-7 is mapped for netpol, not rbac.
	result := r.Resolve("rbac", []string{"SC-7"})
	if _, ok := result["cmmc"]; ok {
		t.Error("SC-7 should not map for rbac probe type")
	}

	result = r.Resolve("netpol", []string{"SC-7"})
	cmmc := result["cmmc"]
	if len(cmmc) != 2 {
		t.Errorf("expected 2 CMMC controls for netpol/SC-7, got %v", cmmc)
	}
}

func TestResolve_EmptyInputs(t *testing.T) {
	r := setupResolver(t)

	result := r.Resolve("rbac", nil)
	if len(result) != 0 {
		t.Errorf("expected empty result for nil controls, got %v", result)
	}

	result = r.Resolve("rbac", []string{})
	if len(result) != 0 {
		t.Errorf("expected empty result for empty controls, got %v", result)
	}
}

func TestVersion(t *testing.T) {
	r := setupResolver(t)

	v := r.Version()
	if v == "" {
		t.Error("expected non-empty version string")
	}
	// Should contain both framework versions.
	if r.FrameworkCount() != 2 {
		t.Errorf("expected 2 frameworks, got %d", r.FrameworkCount())
	}
}

func TestDeduplication(t *testing.T) {
	// Crosswalk with duplicate mappings for the same control.
	dupeJSON := `{
		"framework_id": "test-dupe",
		"crosswalk_version": "1.0.0",
		"mappings": [
			{"profile": "rbac", "nist_control": "AC-3", "control_ids": ["CTRL-1"]},
			{"profile": "rbac", "nist_control": "AC-3", "control_ids": ["CTRL-1", "CTRL-2"]}
		]
	}`

	r := NewResolver()
	_ = r.LoadFramework([]byte(dupeJSON))

	result := r.Resolve("rbac", []string{"AC-3"})
	ids := result["test-dupe"]
	if len(ids) != 2 {
		t.Errorf("expected 2 deduplicated controls, got %v", ids)
	}
}
