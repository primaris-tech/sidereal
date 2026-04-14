package discovery

import (
	"context"
	"fmt"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	siderealv1alpha1 "github.com/primaris-tech/sidereal/api/v1alpha1"
)

// AdmissionDiscoverer generates admission probe recommendations from
// ValidatingWebhookConfiguration and MutatingWebhookConfiguration resources.
type AdmissionDiscoverer struct {
	excluded map[string]bool
}

func (d *AdmissionDiscoverer) Name() string { return "admission" }

func (d *AdmissionDiscoverer) Discover(ctx context.Context, c client.Client) ([]Recommendation, error) {
	var recs []Recommendation

	if webhookRecs, err := d.discoverValidatingWebhooks(ctx, c); err == nil {
		recs = append(recs, webhookRecs...)
	}

	if mutatingRecs, err := d.discoverMutatingWebhooks(ctx, c); err == nil {
		recs = append(recs, mutatingRecs...)
	}

	return recs, nil
}

func (d *AdmissionDiscoverer) discoverValidatingWebhooks(ctx context.Context, c client.Client) ([]Recommendation, error) {
	var webhooks admissionregistrationv1.ValidatingWebhookConfigurationList
	if err := c.List(ctx, &webhooks); err != nil {
		return nil, fmt.Errorf("failed to list ValidatingWebhookConfigurations: %w", err)
	}

	var recs []Recommendation

	for i := range webhooks.Items {
		wh := &webhooks.Items[i]

		if isSystemWebhook(wh.Name) {
			continue
		}

		source := corev1.ObjectReference{
			Kind:       "ValidatingWebhookConfiguration",
			Name:       wh.Name,
			APIVersion: "admissionregistration.k8s.io/v1",
			UID:        wh.UID,
		}

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
		} else if isGatekeeperWebhook(wh.Name) {
			confidence = siderealv1alpha1.ConfidenceHigh
			rationale = fmt.Sprintf("OPA/Gatekeeper webhook %s enforces constraint policies. "+
				"An admission probe can verify that Gatekeeper constraints are rejecting non-compliant resources.",
				wh.Name)
		}

		// Resolve a target namespace that is actually in scope for this webhook.
		// Using a namespace the webhook doesn't cover would make the probe meaningless.
		var selector *metav1.LabelSelector
		if len(wh.Webhooks) > 0 {
			selector = wh.Webhooks[0].NamespaceSelector
		}
		targetNamespace := d.resolveTargetNamespace(ctx, c, selector)

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

func (d *AdmissionDiscoverer) discoverMutatingWebhooks(ctx context.Context, c client.Client) ([]Recommendation, error) {
	var webhooks admissionregistrationv1.MutatingWebhookConfigurationList
	if err := c.List(ctx, &webhooks); err != nil {
		return nil, fmt.Errorf("failed to list MutatingWebhookConfigurations: %w", err)
	}

	var recs []Recommendation

	for i := range webhooks.Items {
		wh := &webhooks.Items[i]

		if isSystemWebhook(wh.Name) {
			continue
		}

		source := corev1.ObjectReference{
			Kind:       "MutatingWebhookConfiguration",
			Name:       wh.Name,
			APIVersion: "admissionregistration.k8s.io/v1",
			UID:        wh.UID,
		}

		// Mutating webhooks modify resources rather than reject them, so the
		// admission probe's rejection-based test may not be meaningful. Surface
		// these at low confidence so the ISSO can evaluate whether the webhook's
		// failurePolicy or side-effect validation makes a probe worthwhile.
		rationale := fmt.Sprintf("MutatingWebhookConfiguration %s modifies resources at admission time. "+
			"The admission probe tests rejection — verify that this webhook's failurePolicy "+
			"or validation behavior makes a rejection-based probe appropriate before promoting.",
			wh.Name)

		var selector *metav1.LabelSelector
		if len(wh.Webhooks) > 0 {
			selector = wh.Webhooks[0].NamespaceSelector
		}
		targetNamespace := d.resolveTargetNamespace(ctx, c, selector)

		recs = append(recs, Recommendation{
			SourceResource: source,
			Confidence:     siderealv1alpha1.ConfidenceLow,
			Rationale:      rationale,
			ProbeTemplate: siderealv1alpha1.SiderealProbeSpec{
				ProbeType:       siderealv1alpha1.ProbeTypeAdmission,
				TargetNamespace: targetNamespace,
				ExecutionMode:   siderealv1alpha1.ExecutionModeDryRun,
				IntervalSeconds: 21600,
			},
			ControlMappings: map[string][]string{
				"nist-800-53": {"CM-7(2)"},
			},
		})
	}

	return recs, nil
}

// resolveTargetNamespace finds a non-excluded namespace that matches the given
// label selector. If selector is nil (webhook applies to all namespaces) or no
// matching namespace is found, it falls back to "default".
func (d *AdmissionDiscoverer) resolveTargetNamespace(ctx context.Context, c client.Client, selector *metav1.LabelSelector) string {
	if selector == nil {
		return "default"
	}

	labelSel, err := metav1.LabelSelectorAsSelector(selector)
	if err != nil {
		return "default"
	}

	var nsList corev1.NamespaceList
	if err := c.List(ctx, &nsList, &client.ListOptions{LabelSelector: labelSel}); err != nil {
		return "default"
	}

	for _, ns := range nsList.Items {
		if !d.excluded[ns.Name] {
			return ns.Name
		}
	}

	return "default"
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

func isGatekeeperWebhook(name string) bool {
	gatekeeperPrefixes := []string{
		"gatekeeper-",
		"gatekeeper.",
	}
	for _, prefix := range gatekeeperPrefixes {
		if len(name) >= len(prefix) && name[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}
