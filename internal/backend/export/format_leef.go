package export

import (
	"fmt"
	"strings"
)

// LEEFSerializer serializes audit records in IBM QRadar Log Event Extended
// Format (LEEF) v2.0.
//
// LEEF format:
//
//	LEEF:2.0|Sidereal|SecurityProbe|1.0|<eventID>|<tab-separated key=value pairs>
type LEEFSerializer struct{}

func (s *LEEFSerializer) Serialize(record AuditRecord) ([]byte, error) {
	eventID := fmt.Sprintf("%s-%s", record.ProbeType, record.Outcome)

	fields := []string{
		fmt.Sprintf("probeId=%s", leefEscape(record.ProbeID)),
		fmt.Sprintf("probeType=%s", leefEscape(record.ProbeType)),
		fmt.Sprintf("outcome=%s", leefEscape(record.Outcome)),
		fmt.Sprintf("controlEffectiveness=%s", leefEscape(record.ControlEffectiveness)),
		fmt.Sprintf("targetNamespace=%s", leefEscape(record.TargetNamespace)),
		fmt.Sprintf("integrityStatus=%s", leefEscape(record.IntegrityStatus)),
		fmt.Sprintf("durationMs=%d", record.DurationMs),
		fmt.Sprintf("devTime=%s", record.Timestamp.UTC().Format("2006-01-02T15:04:05.000Z")),
		fmt.Sprintf("sev=%d", leefSeverity(record.ControlEffectiveness)),
	}

	if record.Detail != "" {
		fields = append(fields, fmt.Sprintf("msg=%s", leefEscape(record.Detail)))
	}

	for framework, controls := range record.ControlMappings {
		fields = append(fields, fmt.Sprintf("framework_%s=%s",
			leefEscape(framework), leefEscape(strings.Join(controls, ","))))
	}

	line := fmt.Sprintf("LEEF:2.0|Sidereal|SecurityProbe|1.0|%s|\t%s",
		leefEscape(eventID),
		strings.Join(fields, "\t"),
	)

	return []byte(line), nil
}

func (s *LEEFSerializer) ContentType() string { return "text/plain" }
func (s *LEEFSerializer) FormatName() string  { return "leef" }

// leefSeverity maps ControlEffectiveness to LEEF severity (1-10).
func leefSeverity(effectiveness string) int {
	switch effectiveness {
	case "Effective":
		return 1
	case "Degraded":
		return 5
	case "Ineffective":
		return 8
	case "Compromised":
		return 10
	default:
		return 5
	}
}

// leefEscape escapes special characters in LEEF field values.
func leefEscape(s string) string {
	s = strings.ReplaceAll(s, "\t", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", "")
	return s
}
