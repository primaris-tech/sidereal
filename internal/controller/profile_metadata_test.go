package controller

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	v1 "github.com/primaris-tech/sidereal/api/v1alpha1"
)

func TestProfileMetadata(t *testing.T) {
	for _, profile := range []string{"rbac", "acme.compliance", "acme/compliance", "acme-" + strings.Repeat("x", 100), "agency/検査"} {
		t.Run(profile, func(t *testing.T) {
			label := ProbeProfileLabelValue(profile)
			if errs := validation.IsValidLabelValue(label); len(errs) != 0 {
				t.Fatalf("invalid profile label %q: %v", label, errs)
			}
			if len(validation.IsValidLabelValue(profile)) == 0 && label != profile {
				t.Fatalf("existing valid label changed: %q -> %q", profile, label)
			}
			if label != ProbeProfileLabelValue(profile) {
				t.Fatal("profile label must be stable across reconciliations")
			}
		})
	}
	if ProbeProfileLabelValue("acme/check") == ProbeProfileLabelValue("acme-check") {
		t.Fatal("qualified and unqualified profiles must retain distinct labels")
	}
}

func TestProfilePreservedThroughResultAndIncident(t *testing.T) {
	for _, tc := range []struct {
		name, profile    string
		legacy, tampered bool
	}{
		{name: "legacy Job", profile: "rbac", legacy: true},
		{name: "qualified custom", profile: "acme-corp/compliance-check"},
		{name: "long custom", profile: "acme/" + strings.Repeat("a", 100)},
		{name: "tampered custom", profile: "acme-corp/compliance-check", tampered: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			probe := createEnforceProbe("test-profile", "production", tc.profile)
			job := (&ProbeSchedulerReconciler{ProbeGoImage: "test"}).buildProbeJob(probe, testProbeID, "production", "sidereal-hmac-"+testProbeID[:8])
			job.Status = createCompletedJob(tc.profile, probe.Name, "production").Status
			if tc.legacy {
				job.Annotations = nil
			}
			key := make([]byte, 32)
			cm, _ := createSignedResultCM(t, key, string(v1.OutcomeFail), "control failed")
			if tc.tampered {
				cm.Data["result"] = "changed after signing"
			}
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "sidereal-hmac-" + testProbeID[:8], Namespace: SystemNamespace},
				Data:       map[string][]byte{"hmac-key": key},
			}
			c := fake.NewClientBuilder().WithScheme(newTestScheme()).WithObjects(probe, job, cm, secret).WithStatusSubresource(probe).Build()
			r := &ResultReconciler{Client: c}
			if _, err := r.Reconcile(context.Background(), reconcile.Request{NamespacedName: client.ObjectKeyFromObject(job)}); err != nil {
				t.Fatal(err)
			}
			var result v1.SiderealProbeResult
			if err := c.Get(context.Background(), client.ObjectKey{Name: "sidereal-result-" + testProbeID[:8], Namespace: SystemNamespace}, &result); err != nil {
				t.Fatal(err)
			}
			if string(result.Spec.Probe.Profile) != tc.profile {
				t.Fatalf("result lost profile: %q", result.Spec.Probe.Profile)
			}
			wantIntegrity := v1.IntegrityVerified
			if tc.tampered {
				wantIntegrity = v1.IntegrityTamperedResult
			}
			if result.Spec.Result.IntegrityStatus != wantIntegrity {
				t.Fatalf("integrity = %s, want %s", result.Spec.Result.IntegrityStatus, wantIntegrity)
			}
			ir := &IncidentReconciler{Client: c}
			if _, err := ir.Reconcile(context.Background(), reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&result)}); err != nil {
				t.Fatal(err)
			}
			var incident v1.SiderealIncident
			if err := c.Get(context.Background(), client.ObjectKey{Name: "sidereal-incident-" + testProbeID[:8], Namespace: SystemNamespace}, &incident); err != nil {
				t.Fatal(err)
			}
			if string(incident.Spec.Profile) != tc.profile {
				t.Fatalf("incident lost profile: %q", incident.Spec.Profile)
			}
			for _, obj := range []client.Object{job, &result, &incident} {
				if errs := validation.IsValidLabelValue(obj.GetLabels()[ProbeProfileLabel]); len(errs) != 0 {
					t.Fatalf("%T has invalid profile label: %v", obj, errs)
				}
			}
		})
	}
}
