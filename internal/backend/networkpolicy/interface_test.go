package networkpolicy

import "testing"

func TestVerdict_IsEffective(t *testing.T) {
	tests := []struct {
		verdict  Verdict
		expected bool
	}{
		{VerdictDropped, true},
		{VerdictInferredDropped, true},
		{VerdictForwarded, false},
		{VerdictInferredForwarded, false},
		{VerdictIndeterminate, false},
		{Verdict("Unknown"), false},
	}

	for _, tt := range tests {
		t.Run(string(tt.verdict), func(t *testing.T) {
			if got := tt.verdict.IsEffective(); got != tt.expected {
				t.Errorf("Verdict(%q).IsEffective() = %v, want %v", tt.verdict, got, tt.expected)
			}
		})
	}
}
