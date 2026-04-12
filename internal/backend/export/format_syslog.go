package export

import (
	"fmt"
	"strings"
)

// SyslogSerializer serializes audit records as RFC 5424 syslog messages
// with structured data elements.
//
// Format:
//
//	<priority>1 timestamp hostname app-name procid msgid [SD-ELEMENT] msg
//
// SD-ELEMENT contains the probe result fields as structured data parameters.
type SyslogSerializer struct {
	// Hostname is the syslog hostname field. Defaults to "sidereal".
	Hostname string
}

func (s *SyslogSerializer) Serialize(record AuditRecord) ([]byte, error) {
	hostname := s.Hostname
	if hostname == "" {
		hostname = "sidereal"
	}

	priority := syslogPriority(record.ControlEffectiveness)
	timestamp := record.Timestamp.UTC().Format("2006-01-02T15:04:05.000000Z")

	// Structured data element with probe result fields.
	sd := fmt.Sprintf(`[sidereal@49610 probeId="%s" probeType="%s" outcome="%s" controlEffectiveness="%s" targetNamespace="%s" integrityStatus="%s" durationMs="%d"]`,
		syslogEscape(record.ProbeID),
		syslogEscape(record.ProbeType),
		syslogEscape(record.Outcome),
		syslogEscape(record.ControlEffectiveness),
		syslogEscape(record.TargetNamespace),
		syslogEscape(record.IntegrityStatus),
		record.DurationMs,
	)

	msg := record.Detail
	if msg == "" {
		msg = fmt.Sprintf("%s probe %s: %s", record.ProbeType, record.Outcome, record.ControlEffectiveness)
	}

	// RFC 5424: <PRI>VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID SP STRUCTURED-DATA SP MSG
	line := fmt.Sprintf("<%d>1 %s %s sidereal - - %s %s",
		priority,
		timestamp,
		hostname,
		sd,
		msg,
	)

	return []byte(line), nil
}

func (s *SyslogSerializer) ContentType() string { return "text/plain" }
func (s *SyslogSerializer) FormatName() string  { return "syslog" }

// syslogPriority computes the PRI value (facility * 8 + severity).
// Uses facility 16 (local0) and maps effectiveness to syslog severity.
func syslogPriority(effectiveness string) int {
	facility := 16 // local0
	var severity int
	switch effectiveness {
	case "Effective":
		severity = 6 // informational
	case "Degraded":
		severity = 4 // warning
	case "Ineffective":
		severity = 3 // error
	case "Compromised":
		severity = 2 // critical
	default:
		severity = 5 // notice
	}
	return facility*8 + severity
}

// syslogEscape escapes characters that are special in RFC 5424 SD-PARAM values.
func syslogEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, `]`, `\]`)
	return s
}
