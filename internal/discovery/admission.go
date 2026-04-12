package discovery

import (
	"context"
	"fmt"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	siderealv1alpha1 "github.com/primaris-tech/sidereal/api/v1alpha1"
)

// AdmissionDiscoverer generates admission probe recommendations from
// ValidatingWebhookConfiguration resources, Kyverno ClusterPolicies,
// and OPA ConstraintTemplates.
type AdmissionDiscoverer struct{}

func (d *AdmissionDiscoverer) Name() string { return "admission" }

func (d *AdmissionDiscoverer) Discover(ctx context.Context, c client.Client) ([]Recommendation, error) {
	var recs []Recommendation

	// Discover ValidatingWebhookConfigurations.
	webhookRecs, err := d.discoverWebhooks(ctx, c)
	if err == nil {
		recs = append(recs, webhookRecs...)
	}

	return recs, nil
}

func (d *AdmissionDiscoverer) discoverWebhooks(ctx context.Context, c client.Client) ([]Recommendation, error) {
	var webhooks admissionregistrationv1.ValidatingWebhookConfigurationList
	if err := c.List(ctx, &webhooks); err != nil {
		return nil, fmt.Errorf("failed to list ValidatingWebhookConfigurations: %w", err)
	}

	var recs []Recommendation

	for i := range webhooks.Items {
		wh := &webhooks.Items[i]

		// Skip system webhooks.
		if isSystemWebhook(wh.Name) {
			continue
		}

		source := corev1.ObjectReference{
			Kind:       "ValidatingWebhookConfiguration",
			Name:       wh.Name,
			APIVersion: "admissionregistration.k8s.io/v1",
			UID:        wh.UID,
		}

		// Determine confidence. Generic webhooks get medium because we can't
		// derive a known-bad spec automatically. Kyverno/OPA webhooks get
		// higher confidence if we can identify the policy engine.
		confidence := siderealv1alpha1.ConfidenceMedium
		rationale := fmt.Sprintf("ValidatingWebhookConfiguration %s enforces admission policies. "+
			"An admission probe can verify that the webhook rejects non-compliant resources. "+
			"Review and supply a knownBadSpec appropriate for this webhook's policies.",
			wh.Name)

		if isKyvernoWebhook(wh.Name) {
			confidence = siderealv1alpha1.ConfidenceHigh
			rationale = fmt.Sprintf("Kyverno webhook %s enforces cluster policies. "+
				"An admission probe can verify that Kyverno policies are rejecting non-compliant resources.",
				wh.Name)
		}

		// Determine target namespace from the webhook's namespace selector.
		targetNamespace := "default"
		if len(wh.Webhooks) > 0 && wh.Webhooks[0].NamespaceSelector != nil {
			// If a namespace selector exists, use default as a safe target.
			targetNamespace = "default"
		}

		recs = append(recs, Recommendation{
			SourceResource: source,
			Confidence:     confidence,
			Rationale:      rationale,
			ProbeTemplate: siderealv1alpha1.SiderealProbeSpec{
				ProbeType:       siderealv1alpha1.ProbeTypeAdmission,
				TargetNamespace: targetNamespace,
				ExecutionMode:   siderealv1alpha1.ExecutionModeDryRun,
				IntervalSeconds: 21600,
			},
			ControlMappings: map[string][]string{
				"nist-800-53": {"CM-7(5)", "CM-7(2)"},
			},
		})
	}

	return recs, nil
}

func isSystemWebhook(name string) bool {
	systemNames := map[string]bool{
		"sidereal-admission": true,
	}
	return systemNames[name]
}

func isKyvernoWebhook(name string) bool {
	kyvernoPrefixes := []string{
		"kyverno-",
		"kyverno.",
	}
	for _, prefix := range kyvernoPrefixes {
		if len(name) >= len(prefix) && name[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}
