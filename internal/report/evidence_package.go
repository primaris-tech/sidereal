package report

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"time"
)

// EvidencePackageOptions controls what is included in the evidence package.
type EvidencePackageOptions struct {
	IncludeResults   bool
	IncludeIncidents bool
}

// GenerateEvidencePackage produces a ZIP archive containing probe results,
// incidents, and metadata as OSCAL-compatible evidence.
func GenerateEvidencePackage(data *ReportData, opts EvidencePackageOptions) ([]byte, error) {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)

	// Manifest.
	manifest := map[string]interface{}{
		"reportType":  "evidence-package",
		"generatedAt": time.Now().UTC().Format(time.RFC3339),
		"period": map[string]string{
			"from": data.TimeRange.From.Format("2006-01-02"),
			"to":   data.TimeRange.To.Format("2006-01-02"),
		},
		"frameworks":   data.Frameworks,
		"resultCount":  len(data.Results),
		"incidentCount": len(data.Incidents),
	}
	if err := writeJSONToZip(w, "manifest.json", manifest); err != nil {
		return nil, err
	}

	// Probe results.
	if opts.IncludeResults && len(data.Results) > 0 {
		for i, result := range data.Results {
			filename := fmt.Sprintf("results/%03d-%s.json", i, result.Name)
			if err := writeJSONToZip(w, filename, result); err != nil {
				return nil, err
			}
		}
	}

	// Incidents.
	if opts.IncludeIncidents && len(data.Incidents) > 0 {
		for i, incident := range data.Incidents {
			filename := fmt.Sprintf("incidents/%03d-%s.json", i, incident.Name)
			if err := writeJSONToZip(w, filename, incident); err != nil {
				return nil, err
			}
		}
	}

	// Summary.
	summary := map[string]interface{}{
		"effectiveness": ComputeDistribution(data.Results),
		"byProbeType":   ComputeProbeTypeSummaries(data.Results),
	}
	if err := writeJSONToZip(w, "summary.json", summary); err != nil {
		return nil, err
	}

	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("failed to finalize ZIP: %w", err)
	}

	return buf.Bytes(), nil
}

func writeJSONToZip(w *zip.Writer, filename string, data interface{}) error {
	f, err := w.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create ZIP entry %s: %w", filename, err)
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(data)
}
