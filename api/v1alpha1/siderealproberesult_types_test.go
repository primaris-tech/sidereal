package v1alpha1

import (
	"testing"
)

func TestDeriveControlEffectiveness(t *testing.T) {
	tests := []struct {
		outcome  ProbeOutcome
		expected ControlEffectiveness
	}{
		{OutcomePass, EffectivenessEffective},
		{OutcomeDetected, EffectivenessEffective},
		{OutcomeBlocked, EffectivenessEffective},
		{OutcomeRejected, EffectivenessEffective},

		{OutcomeFail, EffectivenessIneffective},
		{OutcomeUndetected, EffectivenessIneffective},
		{OutcomeAccepted, EffectivenessIneffective},
		{OutcomeNotEnforced, EffectivenessIneffective},

		{OutcomeBackendUnreachable, EffectivenessDegraded},
		{OutcomeIndeterminate, EffectivenessDegraded},
		{OutcomeNotApplicable, EffectivenessDegraded},

		{OutcomeTamperedResult, EffectivenessCompromised},
	}

	for _, tc := range tests {
		t.Run(string(tc.outcome), func(t *testing.T) {
			got := DeriveControlEffectiveness(tc.outcome)
			if got != tc.expected {
				t.Errorf("DeriveControlEffectiveness(%s) = %s, want %s", tc.outcome, got, tc.expected)
			}
		})
	}
}
