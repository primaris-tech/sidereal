package export

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

var testRecord = AuditRecord{
	ProbeID:              "probe-abc-123",
	ProbeType:            "rbac",
	Outcome:              "Pass",
	ControlEffectiveness: "Effective",
	Timestamp:            time.Date(2026, 3, 15, 10, 30, 0, 0, time.UTC),
	ControlMappings: map[string][]string{
		"NIST-800-53": {"AC-3", "AC-6"},
	},
	CrosswalkVersion: "1.0.0",
	IntegrityStatus:  "Verified",
	TargetNamespace:  "production",
	Detail:           "All RBAC checks passed",
	DurationMs:       150,
	ExportStatus:     "Pending",
}

var failRecord = AuditRecord{
	ProbeID:              "probe-fail-456",
	ProbeType:            "secret",
	Outcome:              "Fail",
	ControlEffectiveness: "Ineffective",
	Timestamp:            time.Date(2026, 3, 15, 11, 0, 0, 0, time.UTC),
	IntegrityStatus:      "Verified",
	TargetNamespace:      "staging",
	Detail:               "Cross-namespace secret access allowed",
	DurationMs:           230,
	ExportStatus:         "Pending",
}

// --- JSON ---

func TestJSONSerializer(t *testing.T) {
	s := &JSONSerializer{}
	data, err := s.Serialize(testRecord)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var parsed AuditRecord
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if parsed.ProbeID != "probe-abc-123" {
		t.Errorf("expected probeId probe-abc-123, got %q", parsed.ProbeID)
	}
	if parsed.Outcome != "Pass" {
		t.Errorf("expected outcome Pass, got %q", parsed.Outcome)
	}
	if s.ContentType() != "application/json" {
		t.Errorf("unexpected content type: %q", s.ContentType())
	}
	if s.FormatName() != "json" {
		t.Errorf("unexpected format name: %q", s.FormatName())
	}
}

// --- CEF ---

func TestCEFSerializer(t *testing.T) {
	s := &CEFSerializer{}
	data, err := s.Serialize(testRecord)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	line := string(data)
	if !strings.HasPrefix(line, "CEF:0|Sidereal|SecurityProbe|1.0|") {
		t.Errorf("missing CEF header: %q", line)
	}
	if !strings.Contains(line, "probeId=probe-abc-123") {
		t.Error("missing probeId in CEF")
	}
	if !strings.Contains(line, "|1|") {
		t.Error("expected severity 1 for Effective")
	}
}

func TestCEFSeverity(t *testing.T) {
	tests := []struct {
		effectiveness string
		expected      int
	}{
		{"Effective", 1},
		{"Degraded", 5},
		{"Ineffective", 8},
		{"Compromised", 10},
		{"Unknown", 5},
	}
	for _, tt := range tests {
		if got := cefSeverity(tt.effectiveness); got != tt.expected {
			t.Errorf("cefSeverity(%q) = %d, want %d", tt.effectiveness, got, tt.expected)
		}
	}
}

func TestCEFEscape(t *testing.T) {
	input := `pipe|equals=backslash\newline
end`
	escaped := cefEscape(input)
	if strings.Contains(escaped, "|") && !strings.Contains(escaped, `\|`) {
		t.Error("pipe not escaped")
	}
	if strings.Contains(escaped, "=") && !strings.Contains(escaped, `\=`) {
		t.Error("equals not escaped")
	}
}

// --- LEEF ---

func TestLEEFSerializer(t *testing.T) {
	s := &LEEFSerializer{}
	data, err := s.Serialize(testRecord)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	line := string(data)
	if !strings.HasPrefix(line, "LEEF:2.0|Sidereal|SecurityProbe|1.0|") {
		t.Errorf("missing LEEF header: %q", line)
	}
	if !strings.Contains(line, "probeId=probe-abc-123") {
		t.Error("missing probeId in LEEF")
	}
	if !strings.Contains(line, "sev=1") {
		t.Error("expected sev=1 for Effective")
	}
}

func TestLEEFSerializer_Fail(t *testing.T) {
	s := &LEEFSerializer{}
	data, err := s.Serialize(failRecord)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(string(data), "sev=8") {
		t.Error("expected sev=8 for Ineffective")
	}
}

// --- Syslog ---

func TestSyslogSerializer(t *testing.T) {
	s := &SyslogSerializer{Hostname: "probe-node-1"}
	data, err := s.Serialize(testRecord)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	line := string(data)
	// Facility 16 (local0) * 8 + severity 6 (info) = 134
	if !strings.HasPrefix(line, "<134>1 ") {
		t.Errorf("expected PRI <134>, got: %q", line[:20])
	}
	if !strings.Contains(line, "probe-node-1") {
		t.Error("missing hostname")
	}
	if !strings.Contains(line, `[sidereal@49610`) {
		t.Error("missing structured data element")
	}
	if !strings.Contains(line, `probeId="probe-abc-123"`) {
		t.Error("missing probeId in SD")
	}
}

func TestSyslogSerializer_DefaultHostname(t *testing.T) {
	s := &SyslogSerializer{}
	data, err := s.Serialize(testRecord)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(string(data), " sidereal sidereal") {
		t.Error("expected default hostname 'sidereal'")
	}
}

func TestSyslogPriority(t *testing.T) {
	tests := []struct {
		effectiveness string
		expected      int
	}{
		{"Effective", 134},    // 16*8 + 6
		{"Degraded", 132},     // 16*8 + 4
		{"Ineffective", 131},  // 16*8 + 3
		{"Compromised", 130},  // 16*8 + 2
		{"Unknown", 133},      // 16*8 + 5
	}
	for _, tt := range tests {
		if got := syslogPriority(tt.effectiveness); got != tt.expected {
			t.Errorf("syslogPriority(%q) = %d, want %d", tt.effectiveness, got, tt.expected)
		}
	}
}

// --- OCSF ---

func TestOCSFSerializer(t *testing.T) {
	s := &OCSFSerializer{}
	data, err := s.Serialize(testRecord)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("invalid JSON from OCSF: %v", err)
	}

	if parsed["class_uid"] != float64(2001) {
		t.Errorf("expected class_uid 2001, got %v", parsed["class_uid"])
	}
	if parsed["severity"] != "Informational" {
		t.Errorf("expected severity Informational, got %v", parsed["severity"])
	}
	if parsed["status"] != "Success" {
		t.Errorf("expected status Success, got %v", parsed["status"])
	}

	finding, ok := parsed["finding"].(map[string]interface{})
	if !ok {
		t.Fatal("missing finding object")
	}
	if finding["uid"] != "probe-abc-123" {
		t.Errorf("expected finding uid probe-abc-123, got %v", finding["uid"])
	}
}

func TestOCSFSerializer_Fail(t *testing.T) {
	s := &OCSFSerializer{}
	data, err := s.Serialize(failRecord)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var parsed map[string]interface{}
	json.Unmarshal(data, &parsed)

	if parsed["severity"] != "High" {
		t.Errorf("expected severity High for Ineffective, got %v", parsed["severity"])
	}
	if parsed["status"] != "Failure" {
		t.Errorf("expected status Failure, got %v", parsed["status"])
	}
}

func TestOCSFSeverity(t *testing.T) {
	tests := []struct {
		effectiveness string
		expectedID    int
		expectedLabel string
	}{
		{"Effective", 1, "Informational"},
		{"Degraded", 3, "Medium"},
		{"Ineffective", 4, "High"},
		{"Compromised", 5, "Critical"},
		{"Unknown", 0, "Unknown"},
	}
	for _, tt := range tests {
		id, label := ocsfSeverity(tt.effectiveness)
		if id != tt.expectedID || label != tt.expectedLabel {
			t.Errorf("ocsfSeverity(%q) = (%d, %q), want (%d, %q)",
				tt.effectiveness, id, label, tt.expectedID, tt.expectedLabel)
		}
	}
}
