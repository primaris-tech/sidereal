package detection

import (
	"fmt"
	"testing"
	"time"
)

func TestDeriveOutcome_Detected(t *testing.T) {
	alerts := []Alert{
		{RuleName: "test-rule", Timestamp: time.Now()},
	}
	outcome := DeriveOutcome(alerts, nil)
	if outcome != OutcomeDetected {
		t.Errorf("expected Detected, got %q", outcome)
	}
}

func TestDeriveOutcome_Undetected(t *testing.T) {
	outcome := DeriveOutcome(nil, nil)
	if outcome != OutcomeUndetected {
		t.Errorf("expected Undetected, got %q", outcome)
	}
}

func TestDeriveOutcome_EmptySlice(t *testing.T) {
	outcome := DeriveOutcome([]Alert{}, nil)
	if outcome != OutcomeUndetected {
		t.Errorf("expected Undetected for empty slice, got %q", outcome)
	}
}

func TestDeriveOutcome_BackendError(t *testing.T) {
	outcome := DeriveOutcome(nil, fmt.Errorf("connection refused"))
	if outcome != OutcomeBackendUnreachable {
		t.Errorf("expected BackendUnreachable, got %q", outcome)
	}
}

func TestDeriveOutcome_ErrorWithAlerts(t *testing.T) {
	// Error takes precedence even if some alerts were collected before failure.
	alerts := []Alert{{RuleName: "partial"}}
	outcome := DeriveOutcome(alerts, fmt.Errorf("stream interrupted"))
	if outcome != OutcomeBackendUnreachable {
		t.Errorf("expected BackendUnreachable when error present, got %q", outcome)
	}
}

func TestAlert_Fields(t *testing.T) {
	alert := Alert{
		RuleName:    "Escape to Host",
		Timestamp:   time.Date(2026, 1, 15, 10, 30, 0, 0, time.UTC),
		PodName:     "detection-probe-abc",
		Namespace:   "sidereal-system",
		TechniqueID: "T1611",
		Priority:    "Critical",
		Output:      "unshare(CLONE_NEWNS) detected",
		Labels: map[string]string{
			"sidereal.cloud/probe-id": "probe-123",
		},
	}

	if alert.RuleName != "Escape to Host" {
		t.Errorf("unexpected RuleName: %q", alert.RuleName)
	}
	if alert.TechniqueID != "T1611" {
		t.Errorf("unexpected TechniqueID: %q", alert.TechniqueID)
	}
	if alert.Labels["sidereal.cloud/probe-id"] != "probe-123" {
		t.Error("missing probe-id label")
	}
}
