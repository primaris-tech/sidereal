package discovery

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	siderealv1alpha1 "github.com/primaris-tech/sidereal/api/v1alpha1"
)

// SecretDiscoverer generates secret probe recommendations by scanning
// namespaces for Secret resources. It prioritizes namespaces with
// high-value Secrets (TLS certs, API keys, and Opaque secrets with
// sensitive names).
type SecretDiscoverer struct {
	excluded map[string]bool
}

func (d *SecretDiscoverer) Name() string { return "secret" }

func (d *SecretDiscoverer) Discover(ctx context.Context, c client.Client) ([]Recommendation, error) {
	namespaces, err := ListNamespaces(ctx, c, d.excluded)
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
			if isHighValueSecret(secret) {
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
				Profile:         siderealv1alpha1.ProbeProfileSecret,
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

func isHighValueSecret(secret corev1.Secret) bool {
	highValueTypes := map[corev1.SecretType]bool{
		corev1.SecretTypeTLS:                 true,
		corev1.SecretTypeDockerConfigJson:    true,
		corev1.SecretTypeBasicAuth:           true,
		corev1.SecretTypeSSHAuth:             true,
		corev1.SecretTypeServiceAccountToken: true,
	}
	if highValueTypes[secret.Type] {
		return true
	}

	// Opaque is the most common type. Check the name for patterns that
	// suggest credential or key material — these are higher-value targets
	// regardless of type label.
	if secret.Type == corev1.SecretTypeOpaque || secret.Type == "" {
		return hasSensitiveName(secret.Name)
	}

	return false
}

// hasSensitiveName returns true if the secret name suggests it contains
// credentials, keys, tokens, or other high-value material.
func hasSensitiveName(name string) bool {
	name = strings.ToLower(name)
	sensitiveTerms := []string{
		"credential", "credentials",
		"password", "passwd",
		"secret",
		"token",
		"api-key", "apikey",
		"private-key", "privatekey",
		"cert", "certificate",
		"auth",
		"encryption-key",
	}
	for _, term := range sensitiveTerms {
		if strings.Contains(name, term) {
			return true
		}
	}
	return false
}
