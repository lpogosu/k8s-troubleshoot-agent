package snapshot

import (
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// EventsFor returns the events attached to a single object, newest last.
//
// Matching is by kind/namespace/name rather than by UID: a snapshot taken with
// a namespace filter can contain events whose target was not collected, and a
// hand-written fixture has no meaningful UIDs. Kind is compared because
// "web" can be both a Service and a Deployment in the same namespace.
func (s *Snapshot) EventsFor(kind, namespace, name string) []corev1.Event {
	var out []corev1.Event
	for _, e := range s.Events {
		ref := e.InvolvedObject
		if ref.Kind == kind && ref.Namespace == namespace && ref.Name == name {
			out = append(out, e)
		}
	}
	sortEvents(out)
	return out
}

// EventsForContainer narrows an object's events to those the kubelet raised for
// one container. The kubelet writes the container into InvolvedObject.FieldPath
// as `spec.containers{name}`; events without a field path (scheduler, quota)
// belong to the pod as a whole and are returned too.
func (s *Snapshot) EventsForContainer(namespace, pod, container string) []corev1.Event {
	want := []string{
		"spec.containers{" + container + "}",
		"spec.initContainers{" + container + "}",
	}
	var out []corev1.Event
	for _, e := range s.EventsFor("Pod", namespace, pod) {
		if e.InvolvedObject.FieldPath == "" {
			out = append(out, e)
			continue
		}
		for _, w := range want {
			if e.InvolvedObject.FieldPath == w {
				out = append(out, e)
				break
			}
		}
	}
	return out
}

// LatestEvent returns the most recent event with any of the given reasons, or
// nil. Reasons are matched exactly — kubelet reasons are a closed vocabulary,
// and substring matching here would make "Failed" swallow "FailedMount".
func LatestEvent(events []corev1.Event, reasons ...string) *corev1.Event {
	var latest *corev1.Event
	for i := range events {
		e := &events[i]
		matched := len(reasons) == 0
		for _, r := range reasons {
			if e.Reason == r {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		if latest == nil {
			latest = e
			continue
		}
		best, cur := eventTime(latest), eventTime(e)
		if !cur.Before(&best) {
			latest = e
		}
	}
	return latest
}

// eventTime prefers the series/last-observed timestamp and falls back through
// the older fields. Kubernetes fills different ones depending on whether the
// event was deduplicated, and a rule that reads only LastTimestamp sees zero
// for every event emitted by the newer events/v1 path.
func eventTime(e *corev1.Event) metav1.Time {
	if e.Series != nil && !e.Series.LastObservedTime.IsZero() {
		return metav1.Time{Time: e.Series.LastObservedTime.Time}
	}
	if !e.LastTimestamp.IsZero() {
		return e.LastTimestamp
	}
	if !e.EventTime.IsZero() {
		return metav1.Time{Time: e.EventTime.Time}
	}
	return e.FirstTimestamp
}

// EventTime exposes the normalised timestamp of an event.
func EventTime(e *corev1.Event) metav1.Time { return eventTime(e) }

// EventCount reports how many times an event fired, normalising the two
// representations Kubernetes uses.
func EventCount(e *corev1.Event) int32 {
	if e.Series != nil && e.Series.Count > 0 {
		return e.Series.Count
	}
	if e.Count > 0 {
		return e.Count
	}
	return 1
}

func sortEvents(events []corev1.Event) {
	sort.SliceStable(events, func(i, j int) bool {
		ti, tj := eventTime(&events[i]), eventTime(&events[j])
		if ti.Equal(&tj) {
			return events[i].Name < events[j].Name
		}
		return ti.Before(&tj)
	})
}

// Node returns the node with the given name, or nil when it was not collected.
func (s *Snapshot) Node(name string) *corev1.Node {
	for i := range s.Nodes {
		if s.Nodes[i].Name == name {
			return &s.Nodes[i]
		}
	}
	return nil
}

// PVC returns a claim by namespace and name, or nil.
func (s *Snapshot) PVC(namespace, name string) *corev1.PersistentVolumeClaim {
	for i := range s.PersistentVolumeClaims {
		c := &s.PersistentVolumeClaims[i]
		if c.Namespace == namespace && c.Name == name {
			return c
		}
	}
	return nil
}

// PodsMatching returns the pods in a namespace selected by a label selector.
// An empty selector matches nothing: an empty `spec.selector` on a Service
// means "no selector" (endpoints are managed manually), not "every pod".
func (s *Snapshot) PodsMatching(namespace string, selector map[string]string) []corev1.Pod {
	if len(selector) == 0 {
		return nil
	}
	sel := labels.SelectorFromSet(selector)
	var out []corev1.Pod
	for _, p := range s.Pods {
		if p.Namespace == namespace && sel.Matches(labels.Set(p.Labels)) {
			out = append(out, p)
		}
	}
	return out
}

// EndpointSlicesFor returns the slices Kubernetes generated for a Service. The
// link is the standard `kubernetes.io/service-name` label, not ownership: a
// slice can outlive the controller that made it.
func (s *Snapshot) EndpointSlicesFor(namespace, service string) []discoveryv1.EndpointSlice {
	var out []discoveryv1.EndpointSlice
	for _, es := range s.EndpointSlices {
		if es.Namespace == namespace && es.Labels[discoveryv1.LabelServiceName] == service {
			out = append(out, es)
		}
	}
	return out
}

// QuotasIn returns the resource quotas that apply to a namespace.
func (s *Snapshot) QuotasIn(namespace string) []corev1.ResourceQuota {
	var out []corev1.ResourceQuota
	for _, q := range s.ResourceQuotas {
		if q.Namespace == namespace {
			out = append(out, q)
		}
	}
	return out
}

// PodCondition returns a pod condition by type, or nil.
func PodCondition(pod *corev1.Pod, t corev1.PodConditionType) *corev1.PodCondition {
	for i := range pod.Status.Conditions {
		if pod.Status.Conditions[i].Type == t {
			return &pod.Status.Conditions[i]
		}
	}
	return nil
}

// NodeCondition returns a node condition by type, or nil.
func NodeCondition(node *corev1.Node, t corev1.NodeConditionType) *corev1.NodeCondition {
	for i := range node.Status.Conditions {
		if node.Status.Conditions[i].Type == t {
			return &node.Status.Conditions[i]
		}
	}
	return nil
}

// ContainerSpec finds a container (regular or init) in a pod spec by name.
func ContainerSpec(pod *corev1.Pod, name string) *corev1.Container {
	for i := range pod.Spec.Containers {
		if pod.Spec.Containers[i].Name == name {
			return &pod.Spec.Containers[i]
		}
	}
	for i := range pod.Spec.InitContainers {
		if pod.Spec.InitContainers[i].Name == name {
			return &pod.Spec.InitContainers[i]
		}
	}
	return nil
}

// ControllerOf returns a short "Kind/name" description of the object that owns
// the pod, used to point the operator at the thing they can actually edit.
func ControllerOf(pod *corev1.Pod) string {
	for _, ref := range pod.OwnerReferences {
		if ref.Controller != nil && *ref.Controller {
			return ref.Kind + "/" + ref.Name
		}
	}
	return ""
}

// Terminating reports whether the object is already on its way out. Findings
// about a pod that is being deleted are noise: the operator asked for this.
func Terminating(meta *metav1.ObjectMeta) bool {
	return meta.DeletionTimestamp != nil
}

// containsFold reports a case-insensitive substring match. Registry and kubelet
// messages are free text and their capitalisation is not stable across
// versions, so classification of those strings has to be case-insensitive.
func containsFold(haystack, needle string) bool {
	return strings.Contains(strings.ToLower(haystack), strings.ToLower(needle))
}

// MessageMatchesAny reports whether msg contains any of the given fragments.
func MessageMatchesAny(msg string, fragments ...string) bool {
	for _, f := range fragments {
		if containsFold(msg, f) {
			return true
		}
	}
	return false
}
