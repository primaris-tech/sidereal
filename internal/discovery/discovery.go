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
	"strings"

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
	discoverers        []Discoverer
	excludedNamespaces map[string]bool
}

// NewEngine creates a discovery engine with the standard set of discoverers.
// Additional namespaces to exclude can be passed as extra arguments.
func NewEngine(additionalExclusions ...string) *Engine {
	excluded := defaultExcludedNamespaces()
	for _, ns := range additionalExclusions {
		excluded[ns] = true
	}
	return &Engine{
		discoverers: []Discoverer{
			&NetworkPolicyDiscoverer{excluded: excluded},
			&RBACDiscoverer{excluded: excluded},
			&AdmissionDiscoverer{excluded: excluded},
			&SecretDiscoverer{excluded: excluded},
			&DetectionDiscoverer{},
		},
		excludedNamespaces: excluded,
	}
}

// NewEngineWithDiscoverers creates a discovery engine with a custom set of discoverers.
func NewEngineWithDiscoverers(discoverers ...Discoverer) *Engine {
	return &Engine{
		discoverers:        discoverers,
		excludedNamespaces: defaultExcludedNamespaces(),
	}
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

// RunByProfile executes only the discoverer matching the given probe profile.
func (e *Engine) RunByProfile(ctx context.Context, c client.Client, profile siderealv1alpha1.ProbeProfile) ([]Recommendation, error) {
	for _, d := range e.discoverers {
		switch profile {
		case siderealv1alpha1.ProbeProfileNetPol:
			if _, ok := d.(*NetworkPolicyDiscoverer); ok {
				return d.Discover(ctx, c)
			}
		case siderealv1alpha1.ProbeProfileRBAC:
			if _, ok := d.(*RBACDiscoverer); ok {
				return d.Discover(ctx, c)
			}
		case siderealv1alpha1.ProbeProfileAdmission:
			if _, ok := d.(*AdmissionDiscoverer); ok {
				return d.Discover(ctx, c)
			}
		case siderealv1alpha1.ProbeProfileSecret:
			if _, ok := d.(*SecretDiscoverer); ok {
				return d.Discover(ctx, c)
			}
		case siderealv1alpha1.ProbeProfileDetection:
			if _, ok := d.(*DetectionDiscoverer); ok {
				return d.Discover(ctx, c)
			}
		}
	}

	return nil, fmt.Errorf("no discoverer for profile %s", profile)
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
// based on its source resource. The result is a valid RFC 1123 subdomain:
// lowercase, with any character outside [a-z0-9-] replaced by a hyphen,
// and consecutive hyphens collapsed.
func RecommendationName(source corev1.ObjectReference, suffix string) string {
	name := fmt.Sprintf("sidereal-rec-%s-%s", source.Kind, source.Name)
	if source.Namespace != "" {
		name = fmt.Sprintf("sidereal-rec-%s-%s-%s", source.Kind, source.Namespace, source.Name)
	}
	if suffix != "" {
		name = fmt.Sprintf("%s-%s", name, suffix)
	}
	name = sanitizeK8sName(name)
	// Kubernetes name limit.
	if len(name) > 253 {
		hash := sha256.Sum256([]byte(name))
		name = fmt.Sprintf("sidereal-rec-%x", hash[:12])
	}
	return name
}

// sanitizeK8sName converts a string into a valid RFC 1123 subdomain label:
// lowercase, non-alphanumeric characters replaced with hyphens, consecutive
// hyphens collapsed, leading and trailing hyphens trimmed.
func sanitizeK8sName(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	prevHyphen := false
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' {
			b.WriteRune(r)
			prevHyphen = false
		} else {
			if !prevHyphen {
				b.WriteRune('-')
				prevHyphen = true
			}
		}
	}
	return strings.Trim(b.String(), "-")
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

// defaultExcludedNamespaces returns the base set of namespaces always excluded
// from discovery. Operators can extend this via NewEngine.
func defaultExcludedNamespaces() map[string]bool {
	return map[string]bool{
		"kube-system":     true,
		"kube-public":     true,
		"kube-node-lease": true,
		"sidereal-system": true,
	}
}

// ExcludedNamespaces returns the engine's active exclusion set.
func (e *Engine) ExcludedNamespaces() map[string]bool {
	return e.excludedNamespaces
}

// ListNamespaces returns all namespaces not in the excluded set.
func ListNamespaces(ctx context.Context, c client.Client, excluded map[string]bool) ([]string, error) {
	var nsList corev1.NamespaceList
	if err := c.List(ctx, &nsList); err != nil {
		return nil, fmt.Errorf("failed to list namespaces: %w", err)
	}

	var names []string
	for _, ns := range nsList.Items {
		if !excluded[ns.Name] {
			names = append(names, ns.Name)
		}
	}
	sort.Strings(names)
	return names, nil
}
