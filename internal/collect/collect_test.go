package collect

import (
	"context"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/lpogosu/k8s-troubleshoot-agent/internal/snapshot"
)

func TestCollectGathersEveryKindTheRulesNeed(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "web-1", Namespace: "shop"}},
		&corev1.Event{ObjectMeta: metav1.ObjectMeta{Name: "e1", Namespace: "shop"}},
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "shop"}},
		&appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: "db", Namespace: "shop"}},
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "worker-1"}},
		&corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: "data", Namespace: "shop"}},
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "shop"}},
		&discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Name: "web-abc", Namespace: "shop"}},
		&corev1.ResourceQuota{ObjectMeta: metav1.ObjectMeta{Name: "q", Namespace: "shop"}},
	)

	snap, errs := NewWithClient(client, Options{Context: "test"}).Collect(context.Background())
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}

	checks := []struct {
		kind string
		got  int
	}{
		{"pods", len(snap.Pods)},
		{"events", len(snap.Events)},
		{"deployments", len(snap.Deployments)},
		{"statefulsets", len(snap.StatefulSets)},
		{"nodes", len(snap.Nodes)},
		{"pvcs", len(snap.PersistentVolumeClaims)},
		{"services", len(snap.Services)},
		{"endpointslices", len(snap.EndpointSlices)},
		{"resourcequotas", len(snap.ResourceQuotas)},
	}
	for _, c := range checks {
		if c.got != 1 {
			t.Errorf("collected %d %s, want 1", c.got, c.kind)
		}
	}
	if snap.Format != snapshot.Format {
		t.Errorf("format = %q, want %q", snap.Format, snapshot.Format)
	}
	if snap.CapturedAt.IsZero() {
		t.Error("capturedAt must be set: every age the rules compute is relative to it")
	}
}

// TestCollectSurvivesAPartialDenial is the case that decides whether the tool
// is usable by a developer with namespace-scoped rights. Aborting on the first
// Forbidden would make it useless to exactly the people who need it most.
func TestCollectSurvivesAPartialDenial(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "web-1", Namespace: "shop"}},
	)
	client.PrependReactor("list", "nodes", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apiForbidden("nodes")
	})

	snap, errs := NewWithClient(client, Options{}).Collect(context.Background())

	if len(snap.Pods) != 1 {
		t.Errorf("pods were collected despite the node denial: got %d, want 1", len(snap.Pods))
	}
	if len(snap.Nodes) != 0 {
		t.Errorf("nodes should be empty, got %d", len(snap.Nodes))
	}
	if len(errs) != 1 {
		t.Fatalf("got %d errors, want exactly the node one: %v", len(errs), errs)
	}
	// The message must say what the missing access costs, not just repeat the
	// API's own wording.
	if !strings.Contains(errs[0].Error(), "the snapshot will be incomplete") {
		t.Errorf("the forbidden error should explain the consequence, got: %v", errs[0])
	}
}

func TestCollectNamespaceScopeIsRecorded(t *testing.T) {
	client := fake.NewSimpleClientset()
	snap, _ := NewWithClient(client, Options{Namespace: "shop"}).Collect(context.Background())

	if snap.Source.Namespace != "shop" {
		t.Errorf("source namespace = %q, want shop", snap.Source.Namespace)
	}
	if snap.ClusterWide() {
		t.Error("a namespaced collection must not claim cluster-wide scope: rules argue from absence")
	}
}

// TestSanitizeRedactsEnvValues covers the reason snapshots can be handed to
// someone else at all. A pod spec routinely carries a database password in a
// literal env value, and a snapshot is made to be attached to a ticket.
func TestSanitizeRedactsEnvValues(t *testing.T) {
	snap := &snapshot.Snapshot{
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{
				Name:          "web-1",
				ManagedFields: []metav1.ManagedFieldsEntry{{Manager: "kubectl"}},
				Annotations: map[string]string{
					corev1.LastAppliedConfigAnnotation: `{"a lot of json":"..."}`,
					"team":                             "platform",
				},
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name: "app",
					Env: []corev1.EnvVar{
						{Name: "DATABASE_PASSWORD", Value: "hunter2"},
						{Name: "LOG_LEVEL", Value: "debug"},
						{Name: "API_KEY", ValueFrom: &corev1.EnvVarSource{
							SecretKeyRef: &corev1.SecretKeySelector{
								LocalObjectReference: corev1.LocalObjectReference{Name: "creds"},
								Key:                  "api-key",
							},
						}},
					},
				}},
				InitContainers: []corev1.Container{{
					Name: "migrate",
					Env:  []corev1.EnvVar{{Name: "DSN", Value: "postgres://user:pass@db/app"}},
				}},
			},
		}},
	}

	Sanitize(snap, false)

	env := snap.Pods[0].Spec.Containers[0].Env
	if env[0].Value != redactedValue {
		t.Errorf("DATABASE_PASSWORD leaked: %q", env[0].Value)
	}
	if env[1].Value != redactedValue {
		t.Errorf("LOG_LEVEL was not redacted: redaction must not try to guess which values are secret, got %q", env[1].Value)
	}
	// The name and the reference are diagnostic information and must survive:
	// "this env var comes from Secret creds" is exactly what a reader needs.
	if env[0].Name != "DATABASE_PASSWORD" {
		t.Error("the variable name must be kept")
	}
	if env[2].ValueFrom == nil || env[2].ValueFrom.SecretKeyRef.Name != "creds" {
		t.Error("a valueFrom reference holds no secret and must be kept")
	}
	if snap.Pods[0].Spec.InitContainers[0].Env[0].Value != redactedValue {
		t.Error("init container env was not redacted")
	}

	if snap.Pods[0].ManagedFields != nil {
		t.Error("managedFields must be stripped: it is bulk no rule reads")
	}
	if _, ok := snap.Pods[0].Annotations[corev1.LastAppliedConfigAnnotation]; ok {
		t.Error("the last-applied-configuration annotation must be stripped")
	}
	if snap.Pods[0].Annotations["team"] != "platform" {
		t.Error("ordinary annotations must be kept")
	}
}

func TestSanitizeKeepEnvValuesOptOut(t *testing.T) {
	snap := &snapshot.Snapshot{Pods: []corev1.Pod{{
		Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name: "app",
			Env:  []corev1.EnvVar{{Name: "LOG_LEVEL", Value: "debug"}},
		}}},
	}}}

	Sanitize(snap, true)

	if got := snap.Pods[0].Spec.Containers[0].Env[0].Value; got != "debug" {
		t.Errorf("--keep-env-values must leave the value alone, got %q", got)
	}
}

func TestSanitizeDropsNodeImageInventory(t *testing.T) {
	snap := &snapshot.Snapshot{Nodes: []corev1.Node{{
		Status: corev1.NodeStatus{Images: []corev1.ContainerImage{
			{Names: []string{"nginx:1.27"}, SizeBytes: 1234},
		}},
	}}}

	Sanitize(snap, false)

	if snap.Nodes[0].Status.Images != nil {
		t.Error("the node image list is the bulk of a node's JSON and no rule reads it")
	}
}

// apiForbidden builds the error shape apierrors.IsForbidden recognises.
func apiForbidden(resource string) error {
	return &statusError{resource: resource}
}

type statusError struct{ resource string }

func (e *statusError) Error() string {
	return "nodes is forbidden: User \"dev\" cannot list resource \"" + e.resource + "\" at the cluster scope"
}

func (e *statusError) Status() metav1.Status {
	return metav1.Status{
		Status:  metav1.StatusFailure,
		Code:    403,
		Reason:  metav1.StatusReasonForbidden,
		Message: e.Error(),
	}
}
