package controller

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"time"

	"github.com/google/uuid"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	siderealv1alpha1 "github.com/primaris-tech/sidereal/api/v1alpha1"
	siderealhmac "github.com/primaris-tech/sidereal/internal/hmac"
	"github.com/primaris-tech/sidereal/internal/metrics"
)

const (
	// SystemNamespace is the namespace where Sidereal components run.
	SystemNamespace = "sidereal-system"

	// HMACRootSecretName is the name of the root HMAC secret.
	HMACRootSecretName = "sidereal-hmac-root"

	// HMACRootSecretKey is the key within the root secret containing the HMAC key.
	HMACRootSecretKey = "hmac-root-key"

	// JobTTLSeconds is the TTL for completed Jobs before cleanup.
	JobTTLSeconds = 600

	// FingerprintLabel is the mandatory label on all probe Jobs.
	FingerprintLabel = "sidereal.cloud/probe-id"

	// ProbeTypeLabel identifies the probe type on Jobs and results.
	ProbeTypeLabel = "sidereal.cloud/probe-type"

	// ProbeNameLabel references the SiderealProbe resource name.
	ProbeNameLabel = "sidereal.cloud/probe-name"

	// TargetNamespaceLabel identifies the target namespace.
	TargetNamespaceLabel = "sidereal.cloud/target-namespace"
)

// probeServiceAccounts maps probe types to their dedicated ServiceAccount names.
var probeServiceAccounts = map[siderealv1alpha1.ProbeType]string{
	siderealv1alpha1.ProbeTypeRBAC:      "sidereal-probe-rbac",
	siderealv1alpha1.ProbeTypeNetPol:    "sidereal-probe-netpol",
	siderealv1alpha1.ProbeTypeAdmission: "sidereal-probe-admission",
	siderealv1alpha1.ProbeTypeSecret:    "sidereal-probe-secret",
	siderealv1alpha1.ProbeTypeDetection: "sidereal-probe-detection",
}

// probeCommands maps probe types to the binary path within their container image.
// Go probes all live in sidereal-probe-go; each has its own binary.
// The detection probe has its own image (Rust, scratch base).
var probeCommands = map[siderealv1alpha1.ProbeType][]string{
	siderealv1alpha1.ProbeTypeRBAC:      {"/probe-rbac"},
	siderealv1alpha1.ProbeTypeNetPol:    {"/probe-netpol"},
	siderealv1alpha1.ProbeTypeAdmission: {"/probe-admission"},
	siderealv1alpha1.ProbeTypeSecret:    {"/probe-secret"},
	siderealv1alpha1.ProbeTypeDetection: {"/detection-probe"},
}

// ProbeSchedulerReconciler reconciles SiderealProbe resources by scheduling probe Jobs.
type ProbeSchedulerReconciler struct {
	client.Client

	// ProbeGoImage is the unified Go probe image (rbac, secret, admission, netpol).
	// Injected from the PROBE_GO_IMAGE environment variable set by the Helm chart.
	ProbeGoImage string

	// ProbeDetectionImage is the Rust detection probe image.
	// Injected from the PROBE_DETECTION_IMAGE environment variable set by the Helm chart.
	ProbeDetectionImage string

	// RegisteredCustomSAs is the set of ServiceAccount names pre-registered
	// via Helm values for custom probe use. Custom probes referencing an
	// unregistered SA will be rejected. If nil, all SAs are allowed (for testing).
	RegisteredCustomSAs map[string]bool
}

// SetupWithManager registers the reconciler with the controller manager.
func (r *ProbeSchedulerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&siderealv1alpha1.SiderealProbe{}).
		Owns(&batchv1.Job{}).
		Complete(r)
}

// Reconcile handles a single SiderealProbe reconciliation.
func (r *ProbeSchedulerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Fetch the SiderealProbe.
	var probe siderealv1alpha1.SiderealProbe
	if err := r.Get(ctx, req.NamespacedName, &probe); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Check if execution is due.
	if !r.isExecutionDue(&probe) {
		nextIn := r.timeUntilNextExecution(&probe)
		return ctrl.Result{RequeueAfter: nextIn}, nil
	}

	// For detection probes, verify active AO authorization.
	if probe.Spec.ProbeType == siderealv1alpha1.ProbeTypeDetection {
		if err := r.verifyAOAuthorization(ctx, &probe); err != nil {
			logger.Info("detection probe skipped: no active AO authorization", "probe", probe.Name, "error", err)
			return ctrl.Result{RequeueAfter: time.Minute}, nil
		}
	}

	// Resolve target namespaces.
	targetNamespaces, err := r.resolveTargetNamespaces(ctx, &probe)
	if err != nil {
		logger.Error(err, "failed to resolve target namespaces")
		return ctrl.Result{}, err
	}

	// Schedule a Job for each target namespace.
	for _, ns := range targetNamespaces {
		if err := r.scheduleProbeJob(ctx, &probe, ns); err != nil {
			logger.Error(err, "failed to schedule probe job", "namespace", ns)
			return ctrl.Result{}, err
		}
	}

	// Re-fetch before status update to get the current resourceVersion.
	// Job creation triggers the Owns watch which can re-queue the probe and
	// advance the resourceVersion before we reach this point, causing a
	// conflict error if we update the stale in-memory copy.
	if err := r.Get(ctx, req.NamespacedName, &probe); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	now := metav1.Now()
	probe.Status.LastExecutedAt = &now
	if err := r.Status().Update(ctx, &probe); err != nil {
		logger.Error(err, "failed to update probe status")
		return ctrl.Result{}, err
	}

	nextIn := r.timeUntilNextExecution(&probe)
	return ctrl.Result{RequeueAfter: nextIn}, nil
}

// isExecutionDue returns true if the probe should execute now.
func (r *ProbeSchedulerReconciler) isExecutionDue(probe *siderealv1alpha1.SiderealProbe) bool {
	if probe.Status.LastExecutedAt == nil {
		return true
	}

	interval := time.Duration(probe.Spec.IntervalSeconds) * time.Second
	jitter := r.computeJitter(interval)
	nextExecution := probe.Status.LastExecutedAt.Time.Add(interval + jitter)

	return time.Now().After(nextExecution)
}

// timeUntilNextExecution calculates the duration until the next execution.
func (r *ProbeSchedulerReconciler) timeUntilNextExecution(probe *siderealv1alpha1.SiderealProbe) time.Duration {
	if probe.Status.LastExecutedAt == nil {
		return 0
	}

	interval := time.Duration(probe.Spec.IntervalSeconds) * time.Second
	nextExecution := probe.Status.LastExecutedAt.Time.Add(interval)
	remaining := time.Until(nextExecution)

	if remaining < 0 {
		return 0
	}
	return remaining
}

// computeJitter returns a random duration within ±10% of the interval.
func (r *ProbeSchedulerReconciler) computeJitter(interval time.Duration) time.Duration {
	maxJitter := interval / 5 // 20% range (±10%)
	if maxJitter == 0 {
		return 0
	}

	n, err := rand.Int(rand.Reader, big.NewInt(int64(maxJitter)))
	if err != nil {
		return 0
	}
	// Shift to center around zero: subtract half the range for ±10%.
	return time.Duration(n.Int64()) - (maxJitter / 2)
}

// resolveTargetNamespaces returns the list of namespaces to probe.
func (r *ProbeSchedulerReconciler) resolveTargetNamespaces(ctx context.Context, probe *siderealv1alpha1.SiderealProbe) ([]string, error) {
	if probe.Spec.TargetNamespace != "" {
		return []string{probe.Spec.TargetNamespace}, nil
	}

	if probe.Spec.TargetNamespaceSelector != nil {
		selector, err := metav1.LabelSelectorAsSelector(probe.Spec.TargetNamespaceSelector)
		if err != nil {
			return nil, fmt.Errorf("invalid namespace selector: %w", err)
		}

		var nsList corev1.NamespaceList
		if err := r.List(ctx, &nsList, &client.ListOptions{
			LabelSelector: selector,
		}); err != nil {
			return nil, fmt.Errorf("failed to list namespaces: %w", err)
		}

		namespaces := make([]string, 0, len(nsList.Items))
		for _, ns := range nsList.Items {
			namespaces = append(namespaces, ns.Name)
		}
		if len(namespaces) == 0 {
			return nil, fmt.Errorf("no namespaces matched selector %s", labels.Set(probe.Spec.TargetNamespaceSelector.MatchLabels))
		}
		return namespaces, nil
	}

	return nil, fmt.Errorf("probe %s has neither targetNamespace nor targetNamespaceSelector", probe.Name)
}

// verifyAOAuthorization checks for an active SiderealAOAuthorization for detection probes.
func (r *ProbeSchedulerReconciler) verifyAOAuthorization(ctx context.Context, probe *siderealv1alpha1.SiderealProbe) error {
	if probe.Spec.AOAuthorizationRef == "" {
		return fmt.Errorf("detection probe requires aoAuthorizationRef")
	}

	var auth siderealv1alpha1.SiderealAOAuthorization
	if err := r.Get(ctx, types.NamespacedName{
		Name:      probe.Spec.AOAuthorizationRef,
		Namespace: probe.Namespace,
	}, &auth); err != nil {
		return fmt.Errorf("AO authorization %q not found: %w", probe.Spec.AOAuthorizationRef, err)
	}

	if !auth.Status.Active {
		return fmt.Errorf("AO authorization %q is not active", probe.Spec.AOAuthorizationRef)
	}

	return nil
}

// scheduleProbeJob creates a single probe runner Job for the given target namespace.
func (r *ProbeSchedulerReconciler) scheduleProbeJob(ctx context.Context, probe *siderealv1alpha1.SiderealProbe, targetNamespace string) error {
	logger := log.FromContext(ctx)
	probeID := uuid.New().String()

	// Validate custom probe ServiceAccount is registered.
	if probe.Spec.ProbeType == siderealv1alpha1.ProbeTypeCustom {
		if err := r.validateCustomProbe(probe); err != nil {
			return err
		}
	}

	// In dryRun mode, log the Job spec but don't create it.
	if probe.Spec.ExecutionMode == siderealv1alpha1.ExecutionModeDryRun {
		logger.Info("dryRun: would create probe job",
			"probe", probe.Name,
			"probeID", probeID,
			"probeType", probe.Spec.ProbeType,
			"targetNamespace", targetNamespace,
		)
		metrics.ProbeExecutionsTotal.WithLabelValues(
			string(probe.Spec.ProbeType), "DryRun", "Effective",
		).Inc()
		return nil
	}

	// Load the HMAC root key.
	var rootSecret corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{
		Name:      HMACRootSecretName,
		Namespace: SystemNamespace,
	}, &rootSecret); err != nil {
		return fmt.Errorf("failed to load HMAC root secret: %w", err)
	}

	rootKey, ok := rootSecret.Data[HMACRootSecretKey]
	if !ok {
		return fmt.Errorf("HMAC root secret missing key %q", HMACRootSecretKey)
	}

	// Derive per-execution HMAC key.
	execKey, err := siderealhmac.DeriveExecutionKey(rootKey, probeID)
	if err != nil {
		return fmt.Errorf("failed to derive execution key: %w", err)
	}

	// Create the per-execution HMAC Secret.
	hmacSecretName := fmt.Sprintf("sidereal-hmac-%s", probeID[:8])
	hmacSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      hmacSecretName,
			Namespace: SystemNamespace,
			Labels: map[string]string{
				FingerprintLabel: probeID,
			},
		},
		Data: map[string][]byte{
			"hmac-key": execKey,
		},
	}
	if err := ctrl.SetControllerReference(probe, hmacSecret, r.Scheme()); err != nil {
		return fmt.Errorf("failed to set owner reference on HMAC secret: %w", err)
	}
	if err := r.Create(ctx, hmacSecret); err != nil {
		return fmt.Errorf("failed to create HMAC secret: %w", err)
	}

	// Build and create the probe Job.
	job := r.buildProbeJob(probe, probeID, targetNamespace, hmacSecretName)
	if err := ctrl.SetControllerReference(probe, job, r.Scheme()); err != nil {
		return fmt.Errorf("failed to set owner reference on job: %w", err)
	}
	if err := r.Create(ctx, job); err != nil {
		return fmt.Errorf("failed to create probe job: %w", err)
	}

	logger.Info("scheduled probe job",
		"probe", probe.Name,
		"probeID", probeID,
		"job", job.Name,
		"targetNamespace", targetNamespace,
		"executionMode", probe.Spec.ExecutionMode,
	)

	return nil
}

// buildProbeJob constructs the Kubernetes Job spec for a probe execution.
func (r *ProbeSchedulerReconciler) buildProbeJob(
	probe *siderealv1alpha1.SiderealProbe,
	probeID string,
	targetNamespace string,
	hmacSecretName string,
) *batchv1.Job {
	sa := r.serviceAccountForProbe(probe)
	image := r.imageForProbe(probe)
	command := r.commandForProbe(probe)
	ttl := int32(JobTTLSeconds)
	backoffLimit := int32(0)

	jobLabels := map[string]string{
		FingerprintLabel:     probeID,
		ProbeTypeLabel:       string(probe.Spec.ProbeType),
		ProbeNameLabel:       probe.Name,
		TargetNamespaceLabel: targetNamespace,
	}

	env := []corev1.EnvVar{
		{Name: "PROBE_ID", Value: probeID},
		{Name: "PROBE_TYPE", Value: string(probe.Spec.ProbeType)},
		{Name: "TARGET_NAMESPACE", Value: targetNamespace},
		{Name: "EXECUTION_MODE", Value: string(probe.Spec.ExecutionMode)},
		{Name: "HMAC_KEY_PATH", Value: "/var/run/secrets/sidereal/hmac-key"},
	}

	// Add MITRE technique ID for detection probes.
	if probe.Spec.ProbeType == siderealv1alpha1.ProbeTypeDetection && probe.Spec.MitreAttackID != "" {
		env = append(env, corev1.EnvVar{Name: "TECHNIQUE_ID", Value: probe.Spec.MitreAttackID})
	}

	// Add custom probe config (opaque JSON passed through to the container).
	if probe.Spec.ProbeType == siderealv1alpha1.ProbeTypeCustom && probe.Spec.CustomProbe != nil && probe.Spec.CustomProbe.Config != nil {
		env = append(env, corev1.EnvVar{Name: "PROBE_CONFIG", Value: string(probe.Spec.CustomProbe.Config.Raw)})
	}

	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("sidereal-probe-%s", probeID[:8]),
			Namespace: SystemNamespace,
			Labels:    jobLabels,
		},
		Spec: batchv1.JobSpec{
			TTLSecondsAfterFinished: &ttl,
			BackoffLimit:            &backoffLimit,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: jobLabels,
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: sa,
					RestartPolicy:      corev1.RestartPolicyNever,
					AutomountServiceAccountToken: ptr.To(true),
					Containers: []corev1.Container{
						{
							Name:            "probe",
							Image:           image,
							ImagePullPolicy: corev1.PullIfNotPresent,
							Command:         command,
							Env:             env,
							Resources: corev1.ResourceRequirements{
								Requests: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("50m"),
									corev1.ResourceMemory: resource.MustParse("64Mi"),
								},
								Limits: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("200m"),
									corev1.ResourceMemory: resource.MustParse("256Mi"),
								},
							},
							SecurityContext: &corev1.SecurityContext{
								RunAsNonRoot:             ptr.To(true),
								ReadOnlyRootFilesystem:   ptr.To(true),
								AllowPrivilegeEscalation: ptr.To(false),
								Capabilities: &corev1.Capabilities{
									Drop: []corev1.Capability{"ALL"},
								},
								SeccompProfile: &corev1.SeccompProfile{
									Type: corev1.SeccompProfileTypeRuntimeDefault,
								},
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "hmac-key",
									MountPath: "/var/run/secrets/sidereal",
									ReadOnly:  true,
								},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "hmac-key",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: hmacSecretName,
								},
							},
						},
					},
				},
			},
		},
	}
}

// serviceAccountForProbe returns the ServiceAccount name for a probe type.
func (r *ProbeSchedulerReconciler) serviceAccountForProbe(probe *siderealv1alpha1.SiderealProbe) string {
	if probe.Spec.ProbeType == siderealv1alpha1.ProbeTypeCustom && probe.Spec.CustomProbe != nil {
		return probe.Spec.CustomProbe.ServiceAccountName
	}
	if sa, ok := probeServiceAccounts[probe.Spec.ProbeType]; ok {
		return sa
	}
	return "sidereal-probe-rbac" // fallback, should not happen
}

// imageForProbe returns the container image for a probe type.
func (r *ProbeSchedulerReconciler) imageForProbe(probe *siderealv1alpha1.SiderealProbe) string {
	if probe.Spec.ProbeType == siderealv1alpha1.ProbeTypeCustom && probe.Spec.CustomProbe != nil {
		return probe.Spec.CustomProbe.Image
	}
	if probe.Spec.ProbeType == siderealv1alpha1.ProbeTypeDetection {
		return r.ProbeDetectionImage
	}
	return r.ProbeGoImage
}

// commandForProbe returns the container command for a probe type.
func (r *ProbeSchedulerReconciler) commandForProbe(probe *siderealv1alpha1.SiderealProbe) []string {
	if probe.Spec.ProbeType == siderealv1alpha1.ProbeTypeCustom {
		return nil // custom probes define their own entrypoint
	}
	if cmd, ok := probeCommands[probe.Spec.ProbeType]; ok {
		return cmd
	}
	return []string{"/probe"}
}

// validateCustomProbe validates that a custom probe's configuration meets
// security requirements:
//  1. CustomProbe spec must be present
//  2. Image must be specified
//  3. ServiceAccountName must be specified
//  4. ServiceAccountName must be pre-registered (if RegisteredCustomSAs is set)
func (r *ProbeSchedulerReconciler) validateCustomProbe(probe *siderealv1alpha1.SiderealProbe) error {
	if probe.Spec.CustomProbe == nil {
		return fmt.Errorf("custom probe %q missing customProbe spec", probe.Name)
	}
	if probe.Spec.CustomProbe.Image == "" {
		return fmt.Errorf("custom probe %q missing image", probe.Name)
	}
	if probe.Spec.CustomProbe.ServiceAccountName == "" {
		return fmt.Errorf("custom probe %q missing serviceAccountName", probe.Name)
	}

	// Validate SA is registered (skip if RegisteredCustomSAs is nil, e.g., in tests).
	if r.RegisteredCustomSAs != nil {
		if !r.RegisteredCustomSAs[probe.Spec.CustomProbe.ServiceAccountName] {
			return fmt.Errorf("custom probe %q references unregistered ServiceAccount %q; register via Helm values customProbes.serviceAccounts",
				probe.Name, probe.Spec.CustomProbe.ServiceAccountName)
		}
	}

	return nil
}
