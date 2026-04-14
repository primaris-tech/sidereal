package discovery

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	siderealv1alpha1 "github.com/primaris-tech/sidereal/api/v1alpha1"
)

// RBACDiscoverer generates rbac probe recommendations from namespaced
// RoleBindings. ClusterRoleBindings are intentionally excluded: the RBAC
// probe validates namespace-scoped enforcement and cannot meaningfully test
// cluster-scoped bindings. ISSOs should audit ClusterRoleBinding subject
// membership via RBAC tooling outside of Sidereal.
type RBACDiscoverer struct{}

func (d *RBACDiscoverer) Name() string { return "rbac" }

func (d *RBACDiscoverer) Discover(ctx context.Context, c client.Client) ([]Recommendation, error) {
	var recs []Recommendation

	// Discover from namespaced RoleBindings.
	namespaces, err := ListNamespaces(ctx, c)
	if err != nil {
		return nil, err
	}

	for _, ns := range namespaces {
		var bindings rbacv1.RoleBindingList
		if err := c.List(ctx, &bindings, client.InNamespace(ns)); err != nil {
			continue
		}

		for i := range bindings.Items {
			rb := &bindings.Items[i]
			if rec, ok := d.roleBindingRecommendation(rb); ok {
				recs = append(recs, rec)
			}
		}
	}

	return recs, nil
}

func (d *RBACDiscoverer) roleBindingRecommendation(rb *rbacv1.RoleBinding) (Recommendation, bool) {
	// Skip system bindings.
	if isSystemBinding(rb.Name) {
		return Recommendation{}, false
	}

	source := corev1.ObjectReference{
		Kind:       "RoleBinding",
		Name:       rb.Name,
		Namespace:  rb.Namespace,
		APIVersion: "rbac.authorization.k8s.io/v1",
		UID:        rb.UID,
	}

	// Determine confidence based on the role reference.
	confidence := siderealv1alpha1.ConfidenceHigh
	rationale := fmt.Sprintf("RoleBinding %s/%s binds role %s. "+
		"An RBAC probe can verify that operations outside the binding's scope are denied.",
		rb.Namespace, rb.Name, rb.RoleRef.Name)

	// High-privilege roles get higher priority.
	if isHighPrivilegeRole(rb.RoleRef.Name) {
		rationale = fmt.Sprintf("RoleBinding %s/%s binds high-privilege role %s. "+
			"An RBAC probe should verify that only authorized subjects have this access.",
			rb.Namespace, rb.Name, rb.RoleRef.Name)
	}

	return Recommendation{
		SourceResource: source,
		Confidence:     confidence,
		Rationale:      rationale,
		ProbeTemplate: siderealv1alpha1.SiderealProbeSpec{
			ProbeType:       siderealv1alpha1.ProbeTypeRBAC,
			TargetNamespace: rb.Namespace,
			ExecutionMode:   siderealv1alpha1.ExecutionModeDryRun,
			IntervalSeconds: 21600,
		},
		ControlMappings: map[string][]string{
			"nist-800-53": {"AC-6(5)", "AC-2"},
		},
	}, true
}

func isSystemBinding(name string) bool {
	systemPrefixes := []string{
		"system:",
		"kubeadm:",
		"calico-",
		"cilium",
		"kube-proxy",
		"sidereal-",
	}
	for _, prefix := range systemPrefixes {
		if len(name) >= len(prefix) && name[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}

func isHighPrivilegeRole(roleName string) bool {
	highPriv := map[string]bool{
		"cluster-admin": true,
		"admin":         true,
		"edit":          true,
	}
	return highPriv[roleName]
}
