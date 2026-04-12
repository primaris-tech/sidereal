package discovery

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	siderealv1alpha1 "github.com/primaris-tech/sidereal/api/v1alpha1"
)

// NetworkPolicyDiscoverer generates netpol probe recommendations from
// existing NetworkPolicy resources in the cluster.
type NetworkPolicyDiscoverer struct{}

func (d *NetworkPolicyDiscoverer) Name() string { return "networkpolicy" }

func (d *NetworkPolicyDiscoverer) Discover(ctx context.Context, c client.Client) ([]Recommendation, error) {
	namespaces, err := ListNamespaces(ctx, c)
	if err != nil {
		return nil, err
	}

	var recs []Recommendation

	for _, ns := range namespaces {
		var policies networkingv1.NetworkPolicyList
		if err := c.List(ctx, &policies, client.InNamespace(ns)); err != nil {
			continue
		}

		for i := range policies.Items {
			np := &policies.Items[i]
			recs = append(recs, d.generateRecommendation(np))
		}
	}

	return recs, nil
}

func (d *NetworkPolicyDiscoverer) generateRecommendation(np *networkingv1.NetworkPolicy) Recommendation {
	source := corev1.ObjectReference{
		Kind:       "NetworkPolicy",
		Name:       np.Name,
		Namespace:  np.Namespace,
		APIVersion: "networking.k8s.io/v1",
		UID:        np.UID,
	}

	confidence := siderealv1alpha1.ConfidenceHigh
	rationale := fmt.Sprintf("NetworkPolicy %s/%s defines network boundaries. "+
		"A netpol probe can verify that the policy is enforced by the CNI.",
		np.Namespace, np.Name)

	// Determine if this is a default-deny policy.
	isDefaultDeny := len(np.Spec.Ingress) == 0 && len(np.Spec.Egress) == 0
	if isDefaultDeny {
		rationale = fmt.Sprintf("NetworkPolicy %s/%s is a default-deny policy. "+
			"A netpol probe can verify that all traffic to pods matching the selector is blocked.",
			np.Namespace, np.Name)
	}

	return Recommendation{
		SourceResource: source,
		Confidence:     confidence,
		Rationale:      rationale,
		ProbeTemplate: siderealv1alpha1.SiderealProbeSpec{
			ProbeType:       siderealv1alpha1.ProbeTypeNetPol,
			TargetNamespace: np.Namespace,
			ExecutionMode:   siderealv1alpha1.ExecutionModeDryRun,
			IntervalSeconds: 21600,
		},
		ControlMappings: map[string][]string{
			"nist-800-53": {"SC-7", "AC-4"},
		},
	}
}
