package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	siderealv1alpha1 "github.com/primaris-tech/sidereal/api/v1alpha1"
	"github.com/primaris-tech/sidereal/internal/crosswalk"
	siderealhmac "github.com/primaris-tech/sidereal/internal/hmac"
	"github.com/primaris-tech/sidereal/internal/metrics"
)

// ProbeRunnerResult is the JSON structure written by probe runners to the result ConfigMap.
type ProbeRunnerResult struct {
	Outcome    string `json:"outcome"`
	Detail     string `json:"detail"`
	DurationMs int64  `json:"durationMs"`
}

// ResultReconciler watches completed probe Jobs, verifies HMAC integrity,
// creates SiderealProbeResult records, and handles tamper detection.
type ResultReconciler struct {
	client.Client
	Crosswalk *crosswalk.Resolver
}

// SetupWithManager registers the reconciler with the controller manager.
func (r *ResultReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&batchv1.Job{}).
		Complete(r)
}

// Reconcile processes a completed probe Job.
func (r *ResultReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Fetch the Job.
	var job batchv1.Job
	if err := r.Get(ctx, req.NamespacedName, &job); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Only process Jobs with our fingerprint label.
	probeID, ok := job.Labels[FingerprintLabel]
	if !ok {
		return ctrl.Result{}, nil
	}

	// Only process completed Jobs.
	if !isJobComplete(&job) {
		return ctrl.Result{}, nil
	}

	// Check if we already processed this result (idempotency).
	var existingResults siderealv1alpha1.SiderealProbeResultList
	if err := r.List(ctx, &existingResults, client.MatchingLabels{
		FingerprintLabel: probeID,
	}); err != nil {
		return ctrl.Result{}, err
	}
	if len(existingResults.Items) > 0 {
		return ctrl.Result{}, nil // already processed
	}

	// Read the result ConfigMap.
	resultCMName := fmt.Sprintf("sidereal-result-%s", probeID[:8])
	var resultCM corev1.ConfigMap
	if err := r.Get(ctx, types.NamespacedName{
		Name:      resultCMName,
		Namespace: SystemNamespace,
	}, &resultCM); err != nil {
		logger.Error(err, "failed to read result ConfigMap", "configmap", resultCMName)
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	}

	// Read the HMAC key Secret.
	hmacSecretName := fmt.Sprintf("sidereal-hmac-%s", probeID[:8])
	var hmacSecret corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{
		Name:      hmacSecretName,
		Namespace: SystemNamespace,
	}, &hmacSecret); err != nil {
		logger.Error(err, "failed to read HMAC secret", "secret", hmacSecretName)
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	}

	hmacKey := hmacSecret.Data["hmac-key"]
	resultPayload := resultCM.Data["result"]
	signature := resultCM.Data["hmac"]

	// Verify HMAC.
	probeType := job.Labels[ProbeTypeLabel]
	probeName := job.Labels[ProbeNameLabel]
	targetNamespace := job.Labels[TargetNamespaceLabel]

	err := siderealhmac.VerifyResult(hmacKey, []byte(resultPayload), signature)
	if err != nil {
		return r.handleTamperedResult(ctx, &job, probeID, probeType, probeName, targetNamespace)
	}

	// Parse the result payload.
	var runnerResult ProbeRunnerResult
	if err := json.Unmarshal([]byte(resultPayload), &runnerResult); err != nil {
		logger.Error(err, "failed to parse result payload")
		return r.handleTamperedResult(ctx, &job, probeID, probeType, probeName, targetNamespace)
	}

	// Derive control effectiveness.
	outcome := siderealv1alpha1.ProbeOutcome(runnerResult.Outcome)
	effectiveness := siderealv1alpha1.DeriveControlEffectiveness(outcome)

	// Resolve crosswalk mappings.
	var controlMappings map[string][]string
	var crosswalkVersion string
	var nistControls []string

	probe, probeErr := r.getProbe(ctx, probeName, job.Namespace)
	if probeErr == nil && probe.Spec.ControlMappings != nil {
		nistControls = probe.Spec.ControlMappings["nist-800-53"]
	}

	if r.Crosswalk != nil && len(nistControls) > 0 {
		controlMappings = r.Crosswalk.Resolve(probeType, nistControls)
		crosswalkVersion = r.Crosswalk.Version()
	} else if len(nistControls) > 0 {
		controlMappings = map[string][]string{"nist-800-53": nistControls}
	}

	// Create the SiderealProbeResult.
	now := time.Now().UTC().Format(time.RFC3339Nano)
	probeResult := &siderealv1alpha1.SiderealProbeResult{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("sidereal-result-%s", probeID[:8]),
			Namespace: SystemNamespace,
			Labels: map[string]string{
				FingerprintLabel:                  probeID,
				ProbeTypeLabel:                    probeType,
				ProbeNameLabel:                    probeName,
				TargetNamespaceLabel:              targetNamespace,
				"sidereal.cloud/outcome":          string(outcome),
				"sidereal.cloud/control-effectiveness": string(effectiveness),
			},
		},
		Spec: siderealv1alpha1.SiderealProbeResultSpec{
			Probe: siderealv1alpha1.ProbeResultProbeRef{
				ID:              probeID,
				Type:            siderealv1alpha1.ProbeType(probeType),
				TargetNamespace: targetNamespace,
			},
			Result: siderealv1alpha1.ProbeResultResult{
				Outcome:              outcome,
				ControlEffectiveness: effectiveness,
				ControlMappings:      controlMappings,
				CrosswalkVersion:     crosswalkVersion,
				NistControls:         nistControls,
				IntegrityStatus:      siderealv1alpha1.IntegrityVerified,
				Detail:               runnerResult.Detail,
			},
			Execution: siderealv1alpha1.ProbeResultExecution{
				Timestamp:  now,
				DurationMs: runnerResult.DurationMs,
				JobName:    job.Name,
			},
			Audit: siderealv1alpha1.ProbeResultAudit{
				ExportStatus: siderealv1alpha1.ExportStatusPending,
			},
		},
	}

	if err := r.Create(ctx, probeResult); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to create ProbeResult: %w", err)
	}

	// Update the parent SiderealProbe status.
	if probeErr == nil {
		r.updateProbeStatus(ctx, probe, outcome, effectiveness, probeResult.Name)
	}

	// Record metrics.
	metrics.ProbeExecutionsTotal.WithLabelValues(
		probeType, string(outcome), string(effectiveness),
	).Inc()
	metrics.ProbeDurationSeconds.WithLabelValues(probeType).Observe(
		float64(runnerResult.DurationMs) / 1000.0,
	)

	// Clean up the result ConfigMap and HMAC Secret.
	_ = r.Delete(ctx, &resultCM)
	_ = r.Delete(ctx, &hmacSecret)

	logger.Info("created probe result",
		"probeResult", probeResult.Name,
		"outcome", outcome,
		"effectiveness", effectiveness,
		"probeType", probeType,
		"targetNamespace", targetNamespace,
	)

	return ctrl.Result{}, nil
}

// handleTamperedResult creates a TamperedResult ProbeResult and a SystemAlert.
func (r *ResultReconciler) handleTamperedResult(
	ctx context.Context,
	job *batchv1.Job,
	probeID, probeType, probeName, targetNamespace string,
) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Error(nil, "HMAC verification failed — tampered result detected",
		"probeID", probeID, "job", job.Name)

	metrics.HMACVerificationFailuresTotal.Inc()

	now := time.Now().UTC().Format(time.RFC3339Nano)

	// Create a TamperedResult ProbeResult.
	probeResult := &siderealv1alpha1.SiderealProbeResult{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("sidereal-result-%s", probeID[:8]),
			Namespace: SystemNamespace,
			Labels: map[string]string{
				FingerprintLabel:                  probeID,
				ProbeTypeLabel:                    probeType,
				ProbeNameLabel:                    probeName,
				TargetNamespaceLabel:              targetNamespace,
				"sidereal.cloud/outcome":          string(siderealv1alpha1.OutcomeTamperedResult),
				"sidereal.cloud/control-effectiveness": string(siderealv1alpha1.EffectivenessCompromised),
			},
		},
		Spec: siderealv1alpha1.SiderealProbeResultSpec{
			Probe: siderealv1alpha1.ProbeResultProbeRef{
				ID:              probeID,
				Type:            siderealv1alpha1.ProbeType(probeType),
				TargetNamespace: targetNamespace,
			},
			Result: siderealv1alpha1.ProbeResultResult{
				Outcome:              siderealv1alpha1.OutcomeTamperedResult,
				ControlEffectiveness: siderealv1alpha1.EffectivenessCompromised,
				IntegrityStatus:      siderealv1alpha1.IntegrityTamperedResult,
				Detail:               "HMAC verification failed — probe result integrity compromised",
			},
			Execution: siderealv1alpha1.ProbeResultExecution{
				Timestamp: now,
				JobName:   job.Name,
			},
			Audit: siderealv1alpha1.ProbeResultAudit{
				ExportStatus: siderealv1alpha1.ExportStatusPending,
			},
		},
	}

	if err := r.Create(ctx, probeResult); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to create tampered ProbeResult: %w", err)
	}

	// Create a SystemAlert.
	alert := &siderealv1alpha1.SiderealSystemAlert{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("sidereal-alert-tampered-%s", probeID[:8]),
			Namespace: SystemNamespace,
		},
		Spec: siderealv1alpha1.SiderealSystemAlertSpec{
			Reason:  siderealv1alpha1.AlertReasonTamperedResult,
			Message: fmt.Sprintf("HMAC verification failed for probe %s (job %s). Probe surface %s suspended.", probeName, job.Name, probeType),
		},
	}

	if err := r.Create(ctx, alert); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to create SystemAlert: %w", err)
	}

	// Update parent probe status.
	probe, err := r.getProbe(ctx, probeName, job.Namespace)
	if err == nil {
		r.updateProbeStatus(ctx, probe,
			siderealv1alpha1.OutcomeTamperedResult,
			siderealv1alpha1.EffectivenessCompromised,
			probeResult.Name,
		)
	}

	metrics.ProbeExecutionsTotal.WithLabelValues(
		probeType,
		string(siderealv1alpha1.OutcomeTamperedResult),
		string(siderealv1alpha1.EffectivenessCompromised),
	).Inc()

	return ctrl.Result{}, nil
}

// getProbe fetches the parent SiderealProbe resource.
func (r *ResultReconciler) getProbe(ctx context.Context, name, namespace string) (*siderealv1alpha1.SiderealProbe, error) {
	var probe siderealv1alpha1.SiderealProbe
	if err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, &probe); err != nil {
		return nil, err
	}
	return &probe, nil
}

// updateProbeStatus updates the SiderealProbe status fields.
func (r *ResultReconciler) updateProbeStatus(
	ctx context.Context,
	probe *siderealv1alpha1.SiderealProbe,
	outcome siderealv1alpha1.ProbeOutcome,
	effectiveness siderealv1alpha1.ControlEffectiveness,
	resultName string,
) {
	probe.Status.LastOutcome = string(outcome)
	probe.Status.LastControlEffectiveness = effectiveness

	if effectiveness == siderealv1alpha1.EffectivenessEffective {
		probe.Status.ConsecutiveFailures = 0
	} else {
		probe.Status.ConsecutiveFailures++
	}

	// Prepend to recent results (keep last 10).
	summary := siderealv1alpha1.ProbeResultSummary{
		Timestamp:            metav1.Now(),
		Outcome:              string(outcome),
		ControlEffectiveness: effectiveness,
		ResultName:           resultName,
	}
	probe.Status.RecentResults = append(
		[]siderealv1alpha1.ProbeResultSummary{summary},
		probe.Status.RecentResults...,
	)
	if len(probe.Status.RecentResults) > 10 {
		probe.Status.RecentResults = probe.Status.RecentResults[:10]
	}

	if err := r.Status().Update(ctx, probe); err != nil {
		log.FromContext(ctx).Error(err, "failed to update probe status")
	}
}

// isJobComplete returns true if the Job has succeeded or failed.
func isJobComplete(job *batchv1.Job) bool {
	for _, cond := range job.Status.Conditions {
		if (cond.Type == batchv1.JobComplete || cond.Type == batchv1.JobFailed) &&
			cond.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}
