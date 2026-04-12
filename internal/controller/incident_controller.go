package controller

import (
	"context"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	siderealv1alpha1 "github.com/primaris-tech/sidereal/api/v1alpha1"
	"github.com/primaris-tech/sidereal/internal/webhook"
)

// IncidentReconciler watches SiderealProbeResult resources and creates
// SiderealIncident records when a control failure is detected in enforce mode.
// It also delivers incident payloads to the configured IR webhook.
type IncidentReconciler struct {
	client.Client

	// WebhookClient delivers incident notifications. May be nil if no webhook is configured.
	WebhookClient *webhook.Client
}

// SetupWithManager registers the reconciler with the controller manager.
func (r *IncidentReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&siderealv1alpha1.SiderealProbeResult{}).
		Complete(r)
}

// Reconcile evaluates a SiderealProbeResult and creates a SiderealIncident
// if the following conditions are met:
//  1. The parent SiderealProbe has executionMode: enforce
//  2. The result's controlEffectiveness is Ineffective or Compromised
func (r *IncidentReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Fetch the ProbeResult.
	var probeResult siderealv1alpha1.SiderealProbeResult
	if err := r.Get(ctx, req.NamespacedName, &probeResult); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Check if this result warrants an incident.
	effectiveness := probeResult.Spec.Result.ControlEffectiveness
	if effectiveness != siderealv1alpha1.EffectivenessIneffective &&
		effectiveness != siderealv1alpha1.EffectivenessCompromised {
		return ctrl.Result{}, nil
	}

	// Look up the parent SiderealProbe to check execution mode.
	probeName := probeResult.Labels[ProbeNameLabel]
	if probeName == "" {
		return ctrl.Result{}, nil
	}

	var probe siderealv1alpha1.SiderealProbe
	if err := r.Get(ctx, types.NamespacedName{
		Name:      probeName,
		Namespace: probeResult.Namespace,
	}, &probe); err != nil {
		// If the probe doesn't exist, we can't determine execution mode.
		logger.Error(err, "failed to get parent probe", "probe", probeName)
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Only create incidents in enforce mode.
	if probe.Spec.ExecutionMode != siderealv1alpha1.ExecutionModeEnforce {
		return ctrl.Result{}, nil
	}

	// Check if an incident already exists for this probe result.
	var existingIncidents siderealv1alpha1.SiderealIncidentList
	if err := r.List(ctx, &existingIncidents, client.InNamespace(probeResult.Namespace),
		client.MatchingLabels{FingerprintLabel: probeResult.Labels[FingerprintLabel]}); err != nil {
		return ctrl.Result{}, err
	}
	if len(existingIncidents.Items) > 0 {
		return ctrl.Result{}, nil // already created
	}

	// Build the incident.
	incident := r.buildIncident(&probeResult, &probe)

	if err := r.Create(ctx, incident); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to create SiderealIncident: %w", err)
	}

	logger.Info("created incident",
		"incident", incident.Name,
		"severity", incident.Spec.Severity,
		"probeType", incident.Spec.ProbeType,
		"targetNamespace", incident.Spec.TargetNamespace,
	)

	// Deliver to IR webhook.
	if r.WebhookClient != nil {
		if err := r.deliverWebhook(ctx, incident); err != nil {
			logger.Error(err, "webhook delivery failed", "incident", incident.Name)
			incident.Spec.WebhookDeliveryStatus = siderealv1alpha1.WebhookFailed
		} else {
			incident.Spec.WebhookDeliveryStatus = siderealv1alpha1.WebhookDelivered
		}

		if err := r.Update(ctx, incident); err != nil {
			logger.Error(err, "failed to update webhook delivery status")
		}
	}

	return ctrl.Result{}, nil
}

// buildIncident creates a SiderealIncident from a ProbeResult and its parent Probe.
func (r *IncidentReconciler) buildIncident(
	result *siderealv1alpha1.SiderealProbeResult,
	probe *siderealv1alpha1.SiderealProbe,
) *siderealv1alpha1.SiderealIncident {
	probeID := result.Labels[FingerprintLabel]
	severity := deriveSeverity(result.Spec.Result.ControlEffectiveness)

	// Extract the primary NIST control from the probe's control mappings.
	var controlID string
	if probe.Spec.ControlMappings != nil {
		if nist, ok := probe.Spec.ControlMappings["nist-800-53"]; ok && len(nist) > 0 {
			controlID = nist[0]
		}
	}

	return &siderealv1alpha1.SiderealIncident{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("sidereal-incident-%s", probeID[:8]),
			Namespace: result.Namespace,
			Labels: map[string]string{
				FingerprintLabel:     probeID,
				ProbeTypeLabel:       string(probe.Spec.ProbeType),
				TargetNamespaceLabel: result.Spec.Probe.TargetNamespace,
			},
		},
		Spec: siderealv1alpha1.SiderealIncidentSpec{
			ProbeResultRef:        result.Name,
			ControlID:             controlID,
			MitreID:               probe.Spec.MitreAttackID,
			Description:           result.Spec.Result.Detail,
			Severity:              severity,
			TargetNamespace:       result.Spec.Probe.TargetNamespace,
			ProbeType:             probe.Spec.ProbeType,
			ControlEffectiveness:  result.Spec.Result.ControlEffectiveness,
			RemediationStatus:     siderealv1alpha1.RemediationOpen,
			WebhookDeliveryStatus: siderealv1alpha1.WebhookPending,
		},
	}
}

// deliverWebhook sends the incident payload to the IR webhook endpoint.
func (r *IncidentReconciler) deliverWebhook(ctx context.Context, incident *siderealv1alpha1.SiderealIncident) error {
	payload := webhook.IncidentPayload{
		IncidentName:         incident.Name,
		ProbeType:            string(incident.Spec.ProbeType),
		TargetNamespace:      incident.Spec.TargetNamespace,
		Outcome:              string(incident.Spec.ControlEffectiveness),
		ControlEffectiveness: string(incident.Spec.ControlEffectiveness),
		Severity:             string(incident.Spec.Severity),
		Description:          incident.Spec.Description,
		ControlID:            incident.Spec.ControlID,
		MitreID:              incident.Spec.MitreID,
		ProbeResultRef:       incident.Spec.ProbeResultRef,
		Timestamp:            time.Now().UTC(),
	}

	return r.WebhookClient.Deliver(ctx, payload)
}

// deriveSeverity maps ControlEffectiveness to IncidentSeverity.
func deriveSeverity(effectiveness siderealv1alpha1.ControlEffectiveness) siderealv1alpha1.IncidentSeverity {
	switch effectiveness {
	case siderealv1alpha1.EffectivenessCompromised:
		return siderealv1alpha1.SeverityCritical
	case siderealv1alpha1.EffectivenessIneffective:
		return siderealv1alpha1.SeverityHigh
	case siderealv1alpha1.EffectivenessDegraded:
		return siderealv1alpha1.SeverityMedium
	default:
		return siderealv1alpha1.SeverityLow
	}
}
