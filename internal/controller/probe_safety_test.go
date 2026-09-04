package controller

import (
	"context"
	"fmt"
	"testing"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	v1 "github.com/primaris-tech/sidereal/api/v1alpha1"
)

func safetyProbe() *v1.SiderealProbe {
	return &v1.SiderealProbe{
		ObjectMeta: metav1.ObjectMeta{Name: "safety-probe", Namespace: SystemNamespace, UID: "safety-probe"},
		Spec: v1.SiderealProbeSpec{
			Profile: v1.ProbeProfileRBAC, TargetNamespace: "production",
			ExecutionMode: v1.ExecutionModeObserve, IntervalSeconds: 300,
		},
	}
}

func safetyScheduler(probe *v1.SiderealProbe, objects ...client.Object) *ProbeSchedulerReconciler {
	root := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: HMACRootSecretName, Namespace: SystemNamespace},
		Data:       map[string][]byte{HMACRootSecretKey: make([]byte, 32)},
	}
	objects = append(objects, probe, root)
	c := fake.NewClientBuilder().WithScheme(newTestScheme()).WithObjects(objects...).
		WithStatusSubresource(probe).Build()
	return &ProbeSchedulerReconciler{Client: c, ProbeGoImage: "test-go", ProbeDetectionImage: "test-detection"}
}

func reconcileSafetyProbe(r *ProbeSchedulerReconciler, probe *v1.SiderealProbe) (reconcile.Result, error) {
	return r.Reconcile(context.Background(), reconcile.Request{NamespacedName: client.ObjectKeyFromObject(probe)})
}

func assertExecutionCount(t *testing.T, r *ProbeSchedulerReconciler, probe *v1.SiderealProbe, want int) {
	t.Helper()
	var jobs batchv1.JobList
	if err := r.List(context.Background(), &jobs); err != nil {
		t.Fatal(err)
	}
	var secrets corev1.SecretList
	if err := r.List(context.Background(), &secrets); err != nil {
		t.Fatal(err)
	}
	if len(jobs.Items) != want || len(secrets.Items) != want+1 {
		t.Fatalf("got %d Jobs and %d Secrets; want %d Jobs and %d Secrets including root", len(jobs.Items), len(secrets.Items), want, want+1)
	}
	if want == 0 {
		var current v1.SiderealProbe
		if err := r.Get(context.Background(), client.ObjectKeyFromObject(probe), &current); err != nil {
			t.Fatal(err)
		}
		if current.Status.LastExecutedAt != nil {
			t.Fatal("blocked execution advanced LastExecutedAt")
		}
	}
}

func TestSchedulerAlertGateAndResume(t *testing.T) {
	for _, mode := range []v1.ExecutionMode{v1.ExecutionModeObserve, v1.ExecutionModeEnforce} {
		t.Run(string(mode), func(t *testing.T) {
			probe := safetyProbe()
			probe.Spec.ExecutionMode = mode
			alert := &v1.SiderealSystemAlert{ObjectMeta: metav1.ObjectMeta{Name: "tamper", Namespace: SystemNamespace}}
			r := safetyScheduler(probe, alert)
			result, err := reconcileSafetyProbe(r, probe)
			if err != nil || result.RequeueAfter <= 0 {
				t.Fatalf("blocked probe should retry: result=%+v err=%v", result, err)
			}
			assertExecutionCount(t, r, probe, 0)
			AcknowledgeAlert(alert, "operator@example.com", "Rotated compromised key")
			if err := r.Update(context.Background(), alert); err != nil {
				t.Fatal(err)
			}
			if _, err := reconcileSafetyProbe(r, probe); err != nil {
				t.Fatal(err)
			}
			assertExecutionCount(t, r, probe, 1)
		})
	}
}

func TestSchedulerRejectsInvalidAcknowledgment(t *testing.T) {
	for _, principal := range []string{"", "system:serviceaccount:sidereal-system:bot"} {
		t.Run(principal, func(t *testing.T) {
			probe := safetyProbe()
			alert := &v1.SiderealSystemAlert{ObjectMeta: metav1.ObjectMeta{Name: "tamper", Namespace: SystemNamespace}}
			AcknowledgeAlert(alert, principal, "Attempted acknowledgment")
			r := safetyScheduler(probe, alert)
			if _, err := reconcileSafetyProbe(r, probe); err != nil {
				t.Fatal(err)
			}
			assertExecutionCount(t, r, probe, 0)
		})
	}
}

type alertListFailure struct{ client.Client }

func (c alertListFailure) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	if _, ok := list.(*v1.SiderealSystemAlertList); ok {
		return fmt.Errorf("alert API unavailable")
	}
	return c.Client.List(ctx, list, opts...)
}

func TestSchedulerAlertReadFailureDeniesExecution(t *testing.T) {
	probe := safetyProbe()
	r := safetyScheduler(probe)
	r.Client = alertListFailure{r.Client}
	if _, err := reconcileSafetyProbe(r, probe); err == nil {
		t.Fatal("expected alert read failure to surface")
	}
	assertExecutionCount(t, r, probe, 0)
}

func TestSchedulerDryRunWithOpenAlert(t *testing.T) {
	probe := safetyProbe()
	probe.Spec.ExecutionMode = v1.ExecutionModeDryRun
	alert := &v1.SiderealSystemAlert{ObjectMeta: metav1.ObjectMeta{Name: "tamper", Namespace: SystemNamespace}}
	r := safetyScheduler(probe, alert)
	if _, err := reconcileSafetyProbe(r, probe); err != nil {
		t.Fatal(err)
	}
	var current v1.SiderealProbe
	if err := r.Get(context.Background(), client.ObjectKeyFromObject(probe), &current); err != nil {
		t.Fatal(err)
	}
	if current.Status.LastExecutedAt == nil {
		t.Fatal("dryRun should still complete configuration evaluation")
	}
	var jobs batchv1.JobList
	if err := r.List(context.Background(), &jobs); err != nil || len(jobs.Items) != 0 {
		t.Fatalf("dryRun created Jobs or failed to list: jobs=%d err=%v", len(jobs.Items), err)
	}
}

func TestSchedulerAuthorizationScope(t *testing.T) {
	tests := []struct {
		name   string
		change func(*v1.SiderealProbe, *v1.SiderealAOAuthorization)
		want   int
	}{
		{name: "valid", want: 1},
		{name: "stale inactive status", change: func(_ *v1.SiderealProbe, a *v1.SiderealAOAuthorization) { a.Status.Active = false }, want: 1},
		{name: "expired with active status", change: func(_ *v1.SiderealProbe, a *v1.SiderealAOAuthorization) {
			a.Spec.ExpiresAt = metav1.NewTime(time.Now().Add(-time.Minute))
		}},
		{name: "future with active status", change: func(_ *v1.SiderealProbe, a *v1.SiderealAOAuthorization) {
			a.Spec.ValidFrom = metav1.NewTime(time.Now().Add(time.Minute))
		}},
		{name: "wrong technique", change: func(p *v1.SiderealProbe, _ *v1.SiderealAOAuthorization) { p.Spec.MitreAttackID = "T9999" }},
		{name: "missing technique", change: func(p *v1.SiderealProbe, _ *v1.SiderealAOAuthorization) { p.Spec.MitreAttackID = "" }},
		{name: "wrong namespace", change: func(p *v1.SiderealProbe, _ *v1.SiderealAOAuthorization) { p.Spec.TargetNamespace = "zz-other" }},
		{name: "wrong reference", change: func(p *v1.SiderealProbe, _ *v1.SiderealAOAuthorization) { p.Spec.AOAuthorizationRef = "missing" }},
		{name: "missing reference", change: func(p *v1.SiderealProbe, _ *v1.SiderealAOAuthorization) { p.Spec.AOAuthorizationRef = "" }},
		{name: "selector partially authorized", change: func(p *v1.SiderealProbe, _ *v1.SiderealAOAuthorization) {
			p.Spec.TargetNamespace = ""
			p.Spec.TargetNamespaceSelector = &metav1.LabelSelector{MatchLabels: map[string]string{"test": "scope"}}
		}},
		{name: "selector fully authorized", change: func(p *v1.SiderealProbe, a *v1.SiderealAOAuthorization) {
			p.Spec.TargetNamespace = ""
			p.Spec.TargetNamespaceSelector = &metav1.LabelSelector{MatchLabels: map[string]string{"test": "scope"}}
			a.Spec.AuthorizedNamespaces = []string{"production", "zz-other"}
		}, want: 2},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			probe := safetyProbe()
			probe.Spec.Profile = v1.ProbeProfileDetection
			probe.Spec.MitreAttackID = "T1611"
			probe.Spec.AOAuthorizationRef = "approved"
			auth := &v1.SiderealAOAuthorization{
				ObjectMeta: metav1.ObjectMeta{Name: "approved", Namespace: SystemNamespace},
				Spec: v1.SiderealAOAuthorizationSpec{
					ValidFrom: metav1.NewTime(time.Now().Add(-time.Hour)), ExpiresAt: metav1.NewTime(time.Now().Add(time.Hour)),
					AuthorizedTechniques: []string{"T1611"}, AuthorizedNamespaces: []string{"production"},
				},
				Status: v1.SiderealAOAuthorizationStatus{Active: true},
			}
			if tc.change != nil {
				tc.change(probe, auth)
			}
			ns1 := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "production", Labels: map[string]string{"test": "scope"}}}
			ns2 := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "zz-other", Labels: map[string]string{"test": "scope"}}}
			r := safetyScheduler(probe, auth, ns1, ns2)
			result, err := reconcileSafetyProbe(r, probe)
			if err != nil {
				t.Fatal(err)
			}
			if tc.want == 0 && result.RequeueAfter <= 0 {
				t.Fatal("blocked authorization should retry")
			}
			assertExecutionCount(t, r, probe, tc.want)
		})
	}
}

func TestSchedulerCustomRegistration(t *testing.T) {
	for _, tc := range []struct {
		name     string
		registry map[string]bool
		want     int
	}{
		{name: "missing registry"},
		{name: "empty registry", registry: map[string]bool{}},
		{name: "unregistered", registry: map[string]bool{"zz-other": true}},
		{name: "disabled entry", registry: map[string]bool{"custom-sa": false}},
		{name: "registered", registry: map[string]bool{"custom-sa": true}, want: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			probe := safetyProbe()
			probe.Spec.Runner = &v1.ProbeRunnerSpec{Type: v1.ProbeRunnerCustom, Custom: &v1.CustomProbeConfig{Image: "example.invalid/probe", ServiceAccountName: "custom-sa"}}
			r := safetyScheduler(probe)
			r.RegisteredCustomSAs = tc.registry
			_, err := reconcileSafetyProbe(r, probe)
			if (err != nil) != (tc.want == 0) {
				t.Fatalf("unexpected reconcile error: %v", err)
			}
			assertExecutionCount(t, r, probe, tc.want)
		})
	}
}
