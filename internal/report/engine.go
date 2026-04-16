// Package report implements the report generation engine for Sidereal.
// It queries SiderealProbeResult and SiderealIncident resources, aggregates
// by controlEffectiveness, groups by framework, and generates five report types:
// continuous monitoring, POA&M, coverage matrix, evidence package, and
// executive summary.
package report

import (
	"context"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client"

	siderealv1alpha1 "github.com/primaris-tech/sidereal/api/v1alpha1"
)

// TimeRange defines the reporting period.
type TimeRange struct {
	From time.Time
	To   time.Time
}

// DefaultTimeRange returns a 30-day lookback from now.
func DefaultTimeRange() TimeRange {
	now := time.Now().UTC()
	return TimeRange{
		From: now.AddDate(0, 0, -30),
		To:   now,
	}
}

// ReportData holds the queried data used across all report types.
type ReportData struct {
	// Results are the probe results within the time range.
	Results []siderealv1alpha1.SiderealProbeResult

	// Incidents are the incidents within the time range.
	Incidents []siderealv1alpha1.SiderealIncident

	// Probes are all active SiderealProbe resources.
	Probes []siderealv1alpha1.SiderealProbe

	// TimeRange is the reporting period.
	TimeRange TimeRange

	// Frameworks is the list of frameworks to include.
	Frameworks []string
}

// EffectivenessDistribution counts results by controlEffectiveness.
type EffectivenessDistribution struct {
	Effective   int `json:"effective"`
	Ineffective int `json:"ineffective"`
	Degraded    int `json:"degraded"`
	Compromised int `json:"compromised"`
	Total       int `json:"total"`
}

// ProfileSummary aggregates results for a single probe profile.
type ProfileSummary struct {
	Profile      string                    `json:"profile"`
	TotalRuns    int                       `json:"totalRuns"`
	Distribution EffectivenessDistribution `json:"distribution"`
}

// ControlStatus tracks the status of a single compliance control.
type ControlStatus struct {
	ControlID            string  `json:"controlId"`
	Framework            string  `json:"framework"`
	Profile              string  `json:"profile,omitempty"`
	LastOutcome          string  `json:"lastOutcome,omitempty"`
	LastEffectiveness    string  `json:"lastEffectiveness,omitempty"`
	HasActiveProbe       bool    `json:"hasActiveProbe"`
	TotalExecutions      int     `json:"totalExecutions"`
	EffectiveCount       int     `json:"effectiveCount"`
	EffectivenessPercent float64 `json:"effectivenessPercent"`
}

// QueryReportData fetches all data needed for report generation.
func QueryReportData(ctx context.Context, c client.Client, tr TimeRange, frameworks []string) (*ReportData, error) {
	data := &ReportData{
		TimeRange:  tr,
		Frameworks: frameworks,
	}

	// Query all probe results.
	var results siderealv1alpha1.SiderealProbeResultList
	if err := c.List(ctx, &results); err != nil {
		return nil, err
	}
	data.Results = results.Items

	// Query all incidents.
	var incidents siderealv1alpha1.SiderealIncidentList
	if err := c.List(ctx, &incidents); err != nil {
		return nil, err
	}
	data.Incidents = incidents.Items

	// Query all probes.
	var probes siderealv1alpha1.SiderealProbeList
	if err := c.List(ctx, &probes); err != nil {
		return nil, err
	}
	data.Probes = probes.Items

	return data, nil
}

// ComputeDistribution calculates the effectiveness distribution from results.
func ComputeDistribution(results []siderealv1alpha1.SiderealProbeResult) EffectivenessDistribution {
	var dist EffectivenessDistribution
	for _, r := range results {
		dist.Total++
		switch r.Spec.Result.ControlEffectiveness {
		case siderealv1alpha1.EffectivenessEffective:
			dist.Effective++
		case siderealv1alpha1.EffectivenessIneffective:
			dist.Ineffective++
		case siderealv1alpha1.EffectivenessDegraded:
			dist.Degraded++
		case siderealv1alpha1.EffectivenessCompromised:
			dist.Compromised++
		}
	}
	return dist
}

// ComputeProfileSummaries aggregates results by probe profile.
func ComputeProfileSummaries(results []siderealv1alpha1.SiderealProbeResult) []ProfileSummary {
	byType := make(map[string][]siderealv1alpha1.SiderealProbeResult)
	for _, r := range results {
		pt := string(r.Spec.Probe.Profile)
		byType[pt] = append(byType[pt], r)
	}

	var summaries []ProfileSummary
	for pt, rs := range byType {
		summaries = append(summaries, ProfileSummary{
			Profile:      pt,
			TotalRuns:    len(rs),
			Distribution: ComputeDistribution(rs),
		})
	}
	return summaries
}
