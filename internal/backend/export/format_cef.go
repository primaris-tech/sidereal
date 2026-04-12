package export

import (
	"fmt"
	"strings"
)

// CEFSerializer serializes audit records in ArcSight Common Event Format (CEF).
//
// CEF format:
//
//	CEF:0|Sidereal|SecurityProbe|1.0|<probeType>|<outcome>|<severity>|<extensions>
type CEFSerializer struct{}

func (s *CEFSerializer) Serialize(record AuditRecord) ([]byte, error) {
	severity := cefSeverity(record.ControlEffectiveness)

	extensions := []string{
		fmt.Sprintf("probeId=%s", cefEscape(record.ProbeID)),
		fmt.Sprintf("probeType=%s", cefEscape(record.ProbeType)),
		fmt.Sprintf("outcome=%s", cefEscape(record.Outcome)),
		fmt.Sprintf("controlEffectiveness=%s", cefEscape(record.ControlEffectiveness)),
		fmt.Sprintf("targetNamespace=%s", cefEscape(record.TargetNamespace)),
		fmt.Sprintf("integrityStatus=%s", cefEscape(record.IntegrityStatus)),
		fmt.Sprintf("durationMs=%d", record.DurationMs),
		fmt.Sprintf("rt=%d", record.Timestamp.UnixMilli()),
	}

	if record.Detail != "" {
		extensions = append(extensions, fmt.Sprintf("msg=%s", cefEscape(record.Detail)))
	}

	for framework, controls := range record.ControlMappings {
		extensions = append(extensions, fmt.Sprintf("cs1Label=%s cs1=%s",
			cefEscape(framework), cefEscape(strings.Join(controls, ","))))
	}

	line := fmt.Sprintf("CEF:0|Sidereal|SecurityProbe|1.0|%s|%s|%d|%s",
		cefEscape(record.ProbeType),
		cefEscape(record.Outcome),
		severity,
		strings.Join(extensions, " "),
	)

	return []byte(line), nil
}

func (s *CEFSerializer) ContentType() string { return "text/plain" }
func (s *CEFSerializer) FormatName() string  { return "cef" }

// cefSeverity maps ControlEffectiveness to CEF severity (0-10).
func cefSeverity(effectiveness string) int {
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

// cefEscape escapes special characters in CEF field values.
func cefEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `|`, `\|`)
	s = strings.ReplaceAll(s, `=`, `\=`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return s
}
