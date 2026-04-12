// Package discovery implements the control discovery engine. It scans a
// Kubernetes cluster for existing security controls (NetworkPolicies, RBAC
// bindings, admission policies, Secrets, detection rules) and generates
// SiderealProbeRecommendation resources for each discovered control boundary.
//
// Discovery is read-only. It creates recommendations but never creates
// SiderealProbe resources automatically. Promotion is an explicit ISSO action.
package discovery

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	siderealv1alpha1 "github.com/primaris-tech/sidereal/api/v1alpha1"
)

// Recommendation is the intermediate representation produced by each discoverer.
// The orchestrator converts these to SiderealProbeRecommendation CRDs.
type Recommendation struct {
	// SourceResource references the cluster resource that prompted this recommendation.
	SourceResource corev1.ObjectReference

	// Confidence indicates how fully the probe was derivable from the source.
	Confidence siderealv1alpha1.RecommendationConfidence

	// Rationale explains why this probe was generated.
	Rationale string

	// ProbeTemplate is the complete SiderealProbe spec to create if promoted.
	ProbeTemplate siderealv1alpha1.SiderealProbeSpec

	// ControlMappings contains suggested multi-framework control mappings.
	ControlMappings map[string][]string
}

// Discoverer scans the cluster for a specific resource type and generates recommendations.
type Discoverer interface {
	// Discover scans the cluster and returns recommendations.
	Discover(ctx context.Context, c client.Client) ([]Recommendation, error)

	// Name returns a human-readable name for this discoverer.
	Name() string
}

// Engine orchestrates all discoverers and deduplicates recommendations.
type Engine struct {
	discoverers []Discoverer
}

// NewEngine creates a discovery engine with the standard set of discoverers.
func NewEngine() *Engine {
	return &Engine{
		discoverers: []Discoverer{
			&NetworkPolicyDiscoverer{},
			&RBACDiscoverer{},
			&AdmissionDiscoverer{},
			&SecretDiscoverer{},
			&DetectionDiscoverer{},
		},
	}
}

// NewEngineWithDiscoverers creates a discovery engine with a custom set of discoverers.
func NewEngineWithDiscoverers(discoverers ...Discoverer) *Engine {
	return &Engine{discoverers: discoverers}
}

// RunAll executes all discoverers and returns deduplicated recommendations.
func (e *Engine) RunAll(ctx context.Context, c client.Client) ([]Recommendation, error) {
	var all []Recommendation

	for _, d := range e.discoverers {
		recs, err := d.Discover(ctx, c)
		if err != nil {
			// Log but continue with other discoverers.
			continue
		}
		all = append(all, recs...)
	}

	return deduplicate(all), nil
}

// RunByType executes only the discoverer matching the given probe type.
func (e *Engine) RunByType(ctx context.Context, c client.Client, probeType siderealv1alpha1.ProbeType) ([]Recommendation, error) {
	for _, d := range e.discoverers {
		switch probeType {
		case siderealv1alpha1.ProbeTypeNetPol:
			if _, ok := d.(*NetworkPolicyDiscoverer); ok {
				return d.Discover(ctx, c)
			}
		case siderealv1alpha1.ProbeTypeRBAC:
			if _, ok := d.(*RBACDiscoverer); ok {
				return d.Discover(ctx, c)
			}
		case siderealv1alpha1.ProbeTypeAdmission:
			if _, ok := d.(*AdmissionDiscoverer); ok {
				return d.Discover(ctx, c)
			}
		case siderealv1alpha1.ProbeTypeSecret:
			if _, ok := d.(*SecretDiscoverer); ok {
				return d.Discover(ctx, c)
			}
		case siderealv1alpha1.ProbeTypeDetection:
			if _, ok := d.(*DetectionDiscoverer); ok {
				return d.Discover(ctx, c)
			}
		}
	}

	return nil, fmt.Errorf("no discoverer for probe type %s", probeType)
}

// HashResource computes a stable hash for a Kubernetes resource for change detection.
func HashResource(obj interface{}) string {
	data, err := json.Marshal(obj)
	if err != nil {
		return ""
	}
	hash := sha256.Sum256(data)
	return fmt.Sprintf("sha256:%x", hash[:8])
}

// RecommendationName generates a deterministic name for a recommendation
// based on its source resource.
func RecommendationName(source corev1.ObjectReference, suffix string) string {
	name := fmt.Sprintf("sidereal-rec-%s-%s", source.Kind, source.Name)
	if source.Namespace != "" {
		name = fmt.Sprintf("sidereal-rec-%s-%s-%s", source.Kind, source.Namespace, source.Name)
	}
	if suffix != "" {
		name = fmt.Sprintf("%s-%s", name, suffix)
	}
	// Kubernetes name limit.
	if len(name) > 253 {
		hash := sha256.Sum256([]byte(name))
		name = fmt.Sprintf("sidereal-rec-%x", hash[:12])
	}
	return name
}

// deduplicate removes recommendations with identical source resources.
// Keeps the first occurrence (highest-priority discoverer).
func deduplicate(recs []Recommendation) []Recommendation {
	seen := map[string]bool{}
	var result []Recommendation
	for _, rec := range recs {
		key := fmt.Sprintf("%s/%s/%s", rec.SourceResource.Kind, rec.SourceResource.Namespace, rec.SourceResource.Name)
		if !seen[key] {
			seen[key] = true
			result = append(result, rec)
		}
	}
	return result
}

// ExcludedNamespaces returns namespaces that should be excluded from discovery.
func ExcludedNamespaces() map[string]bool {
	return map[string]bool{
		"kube-system":      true,
		"kube-public":      true,
		"kube-node-lease":  true,
		"sidereal-system":  true,
	}
}

// ListNamespaces returns all non-excluded namespaces in the cluster.
func ListNamespaces(ctx context.Context, c client.Client) ([]string, error) {
	var nsList corev1.NamespaceList
	if err := c.List(ctx, &nsList); err != nil {
		return nil, fmt.Errorf("failed to list namespaces: %w", err)
	}

	excluded := ExcludedNamespaces()
	var names []string
	for _, ns := range nsList.Items {
		if !excluded[ns.Name] {
			names = append(names, ns.Name)
		}
	}
	sort.Strings(names)
	return names, nil
}
