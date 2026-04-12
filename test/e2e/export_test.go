package e2e

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/primaris-tech/sidereal/internal/backend/export"
)

func TestExport_JSONFormat(t *testing.T) {
	serializer := &export.JSONSerializer{}

	record := export.AuditRecord{
		ProbeID:              "test-probe-json-001",
		ProbeType:            "rbac",
		Outcome:              "Pass",
		ControlEffectiveness: "Effective",
		Timestamp:            time.Now(),
		ControlMappings: map[string][]string{
			"nist-800-53": {"AC-6(5)"},
		},
		CrosswalkVersion: "1.0.0",
		IntegrityStatus:  "Verified",
		TargetNamespace:  "production",
		Detail:           "RBAC deny path verified",
		DurationMs:       42,
		ExportStatus:     "Pending",
	}

	data, err := serializer.Serialize(record)
	if err != nil {
		t.Fatalf("JSON serialization failed: %v", err)
	}

	// Verify it's valid JSON.
	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	// Verify key fields are present.
	if parsed["probeType"] != "rbac" {
		t.Errorf("expected probeType 'rbac', got %v", parsed["probeType"])
	}
	if parsed["outcome"] != "Pass" {
		t.Errorf("expected outcome 'Pass', got %v", parsed["outcome"])
	}
	if parsed["controlEffectiveness"] != "Effective" {
		t.Errorf("expected controlEffectiveness 'Effective', got %v", parsed["controlEffectiveness"])
	}

	if serializer.ContentType() != "application/json" {
		t.Errorf("expected application/json, got %s", serializer.ContentType())
	}
	if serializer.FormatName() != "json" {
		t.Errorf("expected format name 'json', got %s", serializer.FormatName())
	}
}

func TestExport_CEFFormat(t *testing.T) {
	serializer := &export.CEFSerializer{}

	record := export.AuditRecord{
		ProbeID:              "test-probe-cef-001",
		ProbeType:            "netpol",
		Outcome:              "Blocked",
		ControlEffectiveness: "Effective",
		Timestamp:            time.Now(),
		TargetNamespace:      "production",
		Detail:               "NetworkPolicy blocked cross-namespace flow",
		DurationMs:           15,
	}

	data, err := serializer.Serialize(record)
	if err != nil {
		t.Fatalf("CEF serialization failed: %v", err)
	}

	output := string(data)

	// CEF format starts with "CEF:0|"
	if !strings.HasPrefix(output, "CEF:0|") {
		t.Errorf("CEF output should start with 'CEF:0|', got: %s", output[:20])
	}

	// Verify key fields are present in the extension.
	if !strings.Contains(output, "probeType=netpol") {
		t.Error("CEF output should contain probeType")
	}
	if !strings.Contains(output, "outcome=Blocked") {
		t.Error("CEF output should contain outcome")
	}

	if serializer.FormatName() != "cef" {
		t.Errorf("expected format name 'cef', got %s", serializer.FormatName())
	}
}

func TestExport_OCSFFormat(t *testing.T) {
	serializer := &export.OCSFSerializer{}

	record := export.AuditRecord{
		ProbeID:              "test-probe-ocsf-001",
		ProbeType:            "admission",
		Outcome:              "Rejected",
		ControlEffectiveness: "Effective",
		Timestamp:            time.Now(),
		ControlMappings: map[string][]string{
			"nist-800-53": {"CM-7(5)"},
		},
		TargetNamespace: "production",
		Detail:          "Admission policy rejected known-bad spec",
		DurationMs:      30,
	}

	data, err := serializer.Serialize(record)
	if err != nil {
		t.Fatalf("OCSF serialization failed: %v", err)
	}

	// Verify it's valid JSON.
	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("OCSF output is not valid JSON: %v", err)
	}

	// OCSF should have class_uid for compliance finding.
	if _, ok := parsed["class_uid"]; !ok {
		t.Error("OCSF output should contain class_uid")
	}

	if serializer.FormatName() != "ocsf" {
		t.Errorf("expected format name 'ocsf', got %s", serializer.FormatName())
	}
}
