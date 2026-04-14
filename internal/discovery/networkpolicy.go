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
type NetworkPolicyDiscoverer struct {
	excluded map[string]bool
}

func (d *NetworkPolicyDiscoverer) Name() string { return "networkpolicy" }

func (d *NetworkPolicyDiscoverer) Discover(ctx context.Context, c client.Client) ([]Recommendation, error) {
	namespaces, err := ListNamespaces(ctx, c, d.excluded)
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

// defaultDenyDirections returns a human-readable description of which traffic
// directions this NetworkPolicy is default-denying, based on policyTypes and
// the presence or absence of ingress/egress rules.
//
// A direction is default-deny when it appears in policyTypes (explicitly or
// implicitly) and has no corresponding rules. If policyTypes is unset,
// Kubernetes implicitly treats the policy as Ingress-only.
func defaultDenyDirections(np *networkingv1.NetworkPolicy) string {
	var denied []string

	if len(np.Spec.PolicyTypes) == 0 {
		// Implicit Ingress policy: default-deny ingress if no ingress rules.
		if len(np.Spec.Ingress) == 0 {
			denied = append(denied, "ingress")
		}
		return join(denied)
	}

	for _, pt := range np.Spec.PolicyTypes {
		switch pt {
		case networkingv1.PolicyTypeIngress:
			if len(np.Spec.Ingress) == 0 {
				denied = append(denied, "ingress")
			}
		case networkingv1.PolicyTypeEgress:
			if len(np.Spec.Egress) == 0 {
				denied = append(denied, "egress")
			}
		}
	}

	return join(denied)
}

func join(ss []string) string {
	switch len(ss) {
	case 0:
		return ""
	case 1:
		return ss[0]
	default:
		return ss[0] + " and " + ss[1]
	}
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

	if denied := defaultDenyDirections(np); len(denied) > 0 {
		rationale = fmt.Sprintf("NetworkPolicy %s/%s is a default-deny policy for %s traffic. "+
			"A netpol probe can verify that the CNI is enforcing this boundary.",
			np.Namespace, np.Name, denied)
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
