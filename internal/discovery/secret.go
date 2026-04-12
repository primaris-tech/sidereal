package discovery

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	siderealv1alpha1 "github.com/primaris-tech/sidereal/api/v1alpha1"
)

// SecretDiscoverer generates secret probe recommendations by scanning
// namespaces for Secret resources. It prioritizes namespaces with
// high-value Secrets (TLS certs, API keys).
type SecretDiscoverer struct{}

func (d *SecretDiscoverer) Name() string { return "secret" }

func (d *SecretDiscoverer) Discover(ctx context.Context, c client.Client) ([]Recommendation, error) {
	namespaces, err := ListNamespaces(ctx, c)
	if err != nil {
		return nil, err
	}

	var recs []Recommendation

	for _, ns := range namespaces {
		var secrets corev1.SecretList
		if err := c.List(ctx, &secrets, client.InNamespace(ns)); err != nil {
			continue
		}

		if len(secrets.Items) == 0 {
			continue
		}

		// Determine the highest-priority secret type in this namespace.
		hasHighValue := false
		var highValueTypes []string
		for _, secret := range secrets.Items {
			if isHighValueSecret(secret.Type) {
				hasHighValue = true
				highValueTypes = append(highValueTypes, string(secret.Type))
			}
		}

		confidence := siderealv1alpha1.ConfidenceHigh
		rationale := fmt.Sprintf("Namespace %s contains %d Secrets. "+
			"A secret probe can verify that ServiceAccounts from other namespaces cannot read them.",
			ns, len(secrets.Items))

		if hasHighValue {
			rationale = fmt.Sprintf("Namespace %s contains %d Secrets including high-value types (%v). "+
				"Cross-namespace access denial should be verified.",
				ns, len(secrets.Items), highValueTypes)
		}

		source := corev1.ObjectReference{
			Kind:       "Namespace",
			Name:       ns,
			APIVersion: "v1",
		}

		recs = append(recs, Recommendation{
			SourceResource: source,
			Confidence:     confidence,
			Rationale:      rationale,
			ProbeTemplate: siderealv1alpha1.SiderealProbeSpec{
				ProbeType:       siderealv1alpha1.ProbeTypeSecret,
				TargetNamespace: ns,
				ExecutionMode:   siderealv1alpha1.ExecutionModeDryRun,
				IntervalSeconds: 21600,
			},
			ControlMappings: map[string][]string{
				"nist-800-53": {"SC-28", "AC-3"},
			},
		})
	}

	return recs, nil
}

func isHighValueSecret(secretType corev1.SecretType) bool {
	highValue := map[corev1.SecretType]bool{
		corev1.SecretTypeTLS:                  true,
		corev1.SecretTypeDockerConfigJson:     true,
		corev1.SecretTypeBasicAuth:            true,
		corev1.SecretTypeSSHAuth:              true,
		corev1.SecretTypeServiceAccountToken:  true,
	}
	return highValue[secretType]
}
