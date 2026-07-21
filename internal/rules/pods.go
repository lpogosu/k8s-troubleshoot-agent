package rules

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"

	"github.com/lpogosu/k8s-troubleshoot-agent/internal/snapshot"
)

// containerStatus pairs a container status with whether it is an init
// container, because the remediation differs: an init container that never
// succeeds keeps the pod at `Init:0/1` forever and the app container is never
// even created.
type containerStatus struct {
	status *corev1.ContainerStatus
	init   bool
	// index is the position within its own status list, so evidence paths
	// address the object the way kubectl -o jsonpath would.
	index int
}

// statusPath is the JSON path of this status inside the pod, used as evidence
// source so the reader can run kubectl get -o jsonpath and see the same thing.
func (c containerStatus) statusPath() string {
	field := "containerStatuses"
	if c.init {
		field = "initContainerStatuses"
	}
	return fmt.Sprintf("status.%s[%d]", field, c.index)
}

// specPath addresses the container in the pod spec. The spec order and the
// status order are not guaranteed to match, so the name is resolved rather
// than the index reused.
func (c containerStatus) specPath(pod *corev1.Pod, field string) string {
	list, section := pod.Spec.Containers, "containers"
	if c.init {
		list, section = pod.Spec.InitContainers, "initContainers"
	}
	for i := range list {
		if list[i].Name == c.status.Name {
			return fmt.Sprintf("spec.%s[%d].%s", section, i, field)
		}
	}
	return fmt.Sprintf("spec.%s[?(@.name==%q)].%s", section, c.status.Name, field)
}

// allContainerStatuses returns init containers first, matching the order the
// kubelet runs them in.
func allContainerStatuses(pod *corev1.Pod) []containerStatus {
	out := make([]containerStatus, 0, len(pod.Status.InitContainerStatuses)+len(pod.Status.ContainerStatuses))
	for i := range pod.Status.InitContainerStatuses {
		out = append(out, containerStatus{status: &pod.Status.InitContainerStatuses[i], init: true, index: i})
	}
	for i := range pod.Status.ContainerStatuses {
		out = append(out, containerStatus{status: &pod.Status.ContainerStatuses[i], init: false, index: i})
	}
	return out
}

// diagnosable filters out pods that no rule should comment on.
//
// A pod that finished its job or is being deleted is not a fault, and a tool
// that reports one on every `kubectl delete` gets muted within a day.
func diagnosable(pod *corev1.Pod) bool {
	if snapshot.Terminating(&pod.ObjectMeta) {
		return false
	}
	switch pod.Status.Phase {
	case corev1.PodSucceeded:
		return false
	case corev1.PodFailed:
		// A failed pod under a Job is the Job's business; a bare failed pod is
		// still worth explaining.
		return snapshot.ControllerOf(pod) != "Job"
	default:
		return true
	}
}

// podRef builds the object reference for a pod, optionally naming a container.
func podRef(pod *corev1.Pod, container string) ObjectRef {
	return ObjectRef{Kind: "Pod", Namespace: pod.Namespace, Name: pod.Name, Container: container}
}

// ownerHint appends the controller that actually owns the pod template, so the
// reader edits the Deployment rather than patching a pod that will be replaced.
func ownerHint(pod *corev1.Pod) string {
	owner := snapshot.ControllerOf(pod)
	if owner == "" {
		return ""
	}
	return fmt.Sprintf(" The pod is managed by %s, so the fix belongs in that object's pod template.", owner)
}

// describeCmd is the command every diagnosis ends up needing.
func describeCmd(kind, namespace, name string) string {
	return fmt.Sprintf("kubectl -n %s describe %s %s", namespace, kind, name)
}
