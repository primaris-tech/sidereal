package discovery

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"

	siderealv1alpha1 "github.com/primaris-tech/sidereal/api/v1alpha1"
)

// ApprovedTechniques is the set of MITRE ATT&CK technique IDs that Sidereal
// can generate detection probes for. These correspond to techniques in the
// Rust detection probe's syscall catalog.
var ApprovedTechniques = map[string]string{
	"T1053.007": "Container Orchestration Job",
	"T1059.004": "Unix Shell",
	"T1068":     "Exploitation for Privilege Escalation",
	"T1069.003": "Cloud Groups",
	"T1078.001": "Default Accounts",
	"T1552.001": "Credentials In Files",
	"T1552.007": "Container API",
	"T1611":     "Escape to Host",
	"T1613":     "Container and Resource Discovery",
}

// DetectionDiscoverer generates detection probe recommendations by scanning
// for Falco rules (ConfigMaps) and Tetragon TracingPolicy CRs.
type DetectionDiscoverer struct{}

func (d *DetectionDiscoverer) Name() string { return "detection" }

func (d *DetectionDiscoverer) Discover(ctx context.Context, c client.Client) ([]Recommendation, error) {
	var recs []Recommendation

	// Try discovering Tetragon TracingPolicies.
	tetragonRecs, err := d.discoverTetragonPolicies(ctx, c)
	if err == nil {
		recs = append(recs, tetragonRecs...)
	}

	// Try discovering Falco rules (stored in ConfigMaps by convention).
	falcoRecs, err := d.discoverFalcoRules(ctx, c)
	if err == nil {
		recs = append(recs, falcoRecs...)
	}

	return recs, nil
}

func (d *DetectionDiscoverer) discoverTetragonPolicies(ctx context.Context, c client.Client) ([]Recommendation, error) {
	// Tetragon TracingPolicy is a CRD: cilium.io/v1alpha1 TracingPolicy
	tracingPolicyGVK := schema.GroupVersionResource{
		Group:    "cilium.io",
		Version:  "v1alpha1",
		Resource: "tracingpolicies",
	}

	var policies unstructured.UnstructuredList
	policies.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   tracingPolicyGVK.Group,
		Version: tracingPolicyGVK.Version,
		Kind:    "TracingPolicyList",
	})

	if err := c.List(ctx, &policies); err != nil {
		// Tetragon not installed, skip.
		return nil, nil
	}

	var recs []Recommendation
	for _, policy := range policies.Items {
		source := corev1.ObjectReference{
			Kind:       "TracingPolicy",
			Name:       policy.GetName(),
			Namespace:  policy.GetNamespace(),
			APIVersion: "cilium.io/v1alpha1",
			UID:        policy.GetUID(),
		}

		recs = append(recs, Recommendation{
			SourceResource: source,
			Confidence:     siderealv1alpha1.ConfidenceLow,
			Rationale: fmt.Sprintf("Tetragon TracingPolicy %s defines detection rules. "+
				"A detection probe can verify that events matching this policy are detected. "+
				"Map this policy to a MITRE ATT&CK technique from the approved catalog.",
				policy.GetName()),
			ProbeTemplate: siderealv1alpha1.SiderealProbeSpec{
				Profile:         siderealv1alpha1.ProbeProfileDetection,
				TargetNamespace: "default",
				ExecutionMode:   siderealv1alpha1.ExecutionModeDryRun,
				IntervalSeconds: 21600,
			},
			ControlMappings: map[string][]string{
				"nist-800-53": {"SI-4", "AU-6"},
			},
		})
	}

	return recs, nil
}

func (d *DetectionDiscoverer) discoverFalcoRules(ctx context.Context, c client.Client) ([]Recommendation, error) {
	// Falco rules are typically stored in ConfigMaps in the falco namespace.
	falcoNamespaces := []string{"falco", "falco-system"}

	var recs []Recommendation

	for _, ns := range falcoNamespaces {
		var cms corev1.ConfigMapList
		if err := c.List(ctx, &cms, client.InNamespace(ns), client.MatchingLabels{
			"app.kubernetes.io/name": "falco",
		}); err != nil {
			continue
		}

		for _, cm := range cms.Items {
			// Check if this ConfigMap contains Falco rules.
			hasRules := false
			for key := range cm.Data {
				if len(key) > 5 && key[len(key)-5:] == ".yaml" {
					hasRules = true
					break
				}
			}

			if !hasRules {
				continue
			}

			source := corev1.ObjectReference{
				Kind:       "ConfigMap",
				Name:       cm.Name,
				Namespace:  cm.Namespace,
				APIVersion: "v1",
				UID:        cm.UID,
			}

			recs = append(recs, Recommendation{
				SourceResource: source,
				Confidence:     siderealv1alpha1.ConfidenceLow,
				Rationale: fmt.Sprintf("Falco rules ConfigMap %s/%s contains detection rules. "+
					"Detection probes can be generated for rules that map to MITRE ATT&CK techniques "+
					"in the approved catalog. Review and map rules to techniques.",
					cm.Namespace, cm.Name),
				ProbeTemplate: siderealv1alpha1.SiderealProbeSpec{
					Profile:         siderealv1alpha1.ProbeProfileDetection,
					TargetNamespace: "default",
					ExecutionMode:   siderealv1alpha1.ExecutionModeDryRun,
					IntervalSeconds: 21600,
				},
				ControlMappings: map[string][]string{
					"nist-800-53": {"SI-4", "AU-6"},
				},
			})
		}
	}

	return recs, nil
}

