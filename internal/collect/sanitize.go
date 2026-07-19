package collect

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/lpogosu/k8s-troubleshoot-agent/internal/snapshot"
)

// redactedValue replaces literal environment values. It is a fixed string
// rather than a hash so that two snapshots of the same cluster diff cleanly.
const redactedValue = "[redacted by kubediag]"

// Sanitize strips a collected snapshot of two things: bulk that no rule reads,
// and values that must not travel.
//
// The second part is the point of the whole snapshot feature. A snapshot exists
// to be sent to someone who cannot reach the cluster — attached to a ticket,
// pasted into a chat — and a pod spec routinely carries database passwords in
// literal `env` values. Names and `valueFrom` references are kept, because
// "the env var exists and points at Secret X" is diagnostic information;
// the value never is.
//
// Secrets and ConfigMaps are not collected at all, so there is nothing to strip
// there. Rules only ever need to know whether the object exists, and that
// question is answered by the kubelet's FailedMount event.
func Sanitize(s *snapshot.Snapshot, keepEnvValues bool) {
	for i := range s.Pods {
		pod := &s.Pods[i]
		stripMeta(&pod.ObjectMeta)
		if !keepEnvValues {
			redactEnv(pod.Spec.Containers)
			redactEnv(pod.Spec.InitContainers)
			redactEphemeralEnv(pod.Spec.EphemeralContainers)
		}
	}
	for i := range s.Deployments {
		stripMeta(&s.Deployments[i].ObjectMeta)
		if !keepEnvValues {
			redactEnv(s.Deployments[i].Spec.Template.Spec.Containers)
			redactEnv(s.Deployments[i].Spec.Template.Spec.InitContainers)
		}
	}
	for i := range s.StatefulSets {
		stripMeta(&s.StatefulSets[i].ObjectMeta)
		if !keepEnvValues {
			redactEnv(s.StatefulSets[i].Spec.Template.Spec.Containers)
			redactEnv(s.StatefulSets[i].Spec.Template.Spec.InitContainers)
		}
	}
	for i := range s.Nodes {
		stripMeta(&s.Nodes[i].ObjectMeta)
		// Node images are a long list of digests that no rule reads and that
		// makes up most of a node's JSON.
		s.Nodes[i].Status.Images = nil
	}
	for i := range s.Services {
		stripMeta(&s.Services[i].ObjectMeta)
	}
	for i := range s.PersistentVolumeClaims {
		stripMeta(&s.PersistentVolumeClaims[i].ObjectMeta)
	}
	for i := range s.EndpointSlices {
		stripMeta(&s.EndpointSlices[i].ObjectMeta)
	}
	for i := range s.ResourceQuotas {
		stripMeta(&s.ResourceQuotas[i].ObjectMeta)
	}
	for i := range s.Events {
		s.Events[i].ManagedFields = nil
	}
}

// redactEphemeralEnv covers debug containers, which are a separate type that
// embeds the container fields rather than reusing corev1.Container.
func redactEphemeralEnv(containers []corev1.EphemeralContainer) {
	for i := range containers {
		for j := range containers[i].Env {
			if containers[i].Env[j].Value != "" {
				containers[i].Env[j].Value = redactedValue
			}
		}
	}
}

func redactEnv(containers []corev1.Container) {
	for i := range containers {
		for j := range containers[i].Env {
			if containers[i].Env[j].Value != "" {
				containers[i].Env[j].Value = redactedValue
			}
		}
	}
}

// stripMeta removes the metadata that dominates a snapshot's size without
// helping anyone read it: server-side-apply bookkeeping and the full previous
// manifest that client-side apply stores in an annotation.
func stripMeta(meta *metav1.ObjectMeta) {
	meta.ManagedFields = nil
	delete(meta.Annotations, corev1.LastAppliedConfigAnnotation)
	if len(meta.Annotations) == 0 {
		meta.Annotations = nil
	}
}
