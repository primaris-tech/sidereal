package export

import "encoding/json"

// JSONSerializer serializes audit records as JSON. This is the default format.
type JSONSerializer struct{}

func (s *JSONSerializer) Serialize(record AuditRecord) ([]byte, error) {
	return json.Marshal(record)
}

func (s *JSONSerializer) ContentType() string { return "application/json" }
func (s *JSONSerializer) FormatName() string  { return "json" }
