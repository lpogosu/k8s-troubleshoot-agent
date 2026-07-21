package rules

import (
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"

	"github.com/lpogosu/k8s-troubleshoot-agent/internal/snapshot"
)

// serviceEndpointsRule reports a Service that resolves to nothing.
//
// A Service with no ready endpoints still has a ClusterIP, still resolves in
// DNS, and still accepts connections — which then hang or are refused. Callers
// see a network error and start debugging the network. Splitting the two causes
// apart is what makes the finding worth reading: "no pod matches the selector"
// is a label mistake, "pods match but none is ready" is a workload problem that
// KTA006 or KTA002 already explains in detail.
type serviceEndpointsRule struct{}

func (serviceEndpointsRule) ID() string { return "KTA007" }

func (serviceEndpointsRule) Description() string {
	return "Service has no ready endpoints: selector matches nothing, or matching pods are not ready"
}

func (r serviceEndpointsRule) Evaluate(s *snapshot.Snapshot) []Finding {
	var out []Finding
	for i := range s.Services {
		svc := &s.Services[i]
		if !serviceRoutesToPods(svc) {
			continue
		}
		// A namespace-scoped snapshot cannot prove that no pod matches, only
		// that no collected pod does. Arguing from absence on partial data is
		// how a diagnostic tool loses the reader's trust.
		if !s.ClusterWide() && s.Source.Namespace != svc.Namespace {
			continue
		}
		slices := s.EndpointSlicesFor(svc.Namespace, svc.Name)
		ready, notReady := countEndpoints(slices)
		if ready > 0 {
			continue
		}
		all := s.PodsMatching(svc.Namespace, svc.Spec.Selector)
		matching := servable(all)
		// A Service whose backing pods are all terminating is being scaled
		// down or replaced, and it having no endpoints is the intended
		// outcome rather than a fault.
		if len(all) > 0 && len(matching) == 0 {
			continue
		}
		// During the first seconds of a deployment a Service legitimately has
		// no ready endpoints. Firing here would mean every `kubectl apply`
		// produces a critical finding, so the rule waits until either the
		// Service or its pods are old enough for emptiness to mean something.
		if s.Age(&svc.CreationTimestamp) < StartupGrace || allPodsYoungerThanGrace(s, matching) {
			continue
		}
		out = append(out, r.finding(s, svc, slices, matching, notReady))
	}
	return out
}

// serviceRoutesToPods excludes the Service kinds whose endpoints are not
// derived from a selector: ExternalName has no endpoints by design, and a
// selector-less Service is one whose EndpointSlices are maintained by hand or
// by another controller.
func serviceRoutesToPods(svc *corev1.Service) bool {
	if snapshot.Terminating(&svc.ObjectMeta) {
		return false
	}
	if svc.Spec.Type == corev1.ServiceTypeExternalName {
		return false
	}
	return len(svc.Spec.Selector) > 0
}

// servable keeps the pods that Kubernetes would still consider putting behind
// a Service: not being deleted, and not already finished.
func servable(pods []corev1.Pod) []corev1.Pod {
	out := make([]corev1.Pod, 0, len(pods))
	for i := range pods {
		if diagnosable(&pods[i]) {
			out = append(out, pods[i])
		}
	}
	return out
}

// allPodsYoungerThanGrace reports whether every matching pod is still inside
// its start-up window. An empty set is not "young": a selector that matches
// nothing is wrong regardless of how long it has been wrong.
func allPodsYoungerThanGrace(s *snapshot.Snapshot, pods []corev1.Pod) bool {
	if len(pods) == 0 {
		return false
	}
	for i := range pods {
		if s.Age(pods[i].Status.StartTime) >= StartupGrace {
			return false
		}
	}
	return true
}

func countEndpoints(slices []discoveryv1.EndpointSlice) (ready, notReady int) {
	for _, es := range slices {
		for _, ep := range es.Endpoints {
			if ep.Conditions.Ready != nil && *ep.Conditions.Ready {
				ready++
			} else {
				notReady++
			}
		}
	}
	return ready, notReady
}

func (r serviceEndpointsRule) finding(
	s *snapshot.Snapshot,
	svc *corev1.Service,
	slices []discoveryv1.EndpointSlice,
	matching []corev1.Pod,
	notReady int,
) Finding {
	selector := formatSelector(svc.Spec.Selector)

	evidence := []Evidence{
		FieldEvidence("spec.selector", selector),
		FieldEvidence("EndpointSlice ready addresses",
			fmt.Sprintf("0 ready, %d not ready, across %d slice(s)", notReady, len(slices))),
	}

	var title, summary string
	var steps []string

	switch {
	case len(matching) == 0:
		title = "Service selector matches no pod"
		summary = fmt.Sprintf(
			"No pod in namespace %s carries the labels %s, so the Service has nothing to route to. "+
				"Its ClusterIP still resolves and still accepts connections, which is why callers see a "+
				"timeout or a refused connection rather than a DNS failure. The mismatch is almost "+
				"always between the Service's spec.selector and the pod template's metadata.labels — "+
				"note that the Deployment's own spec.selector is a third, separate field that can agree "+
				"with the template while the Service disagrees with both.",
			svc.Namespace, selector)
		evidence = append(evidence, FieldEvidence(
			"pods matching the selector",
			fmt.Sprintf("0 of %d pods in namespace %s", podsInNamespace(s, svc.Namespace), svc.Namespace)))
		if labels := podLabelSample(s, svc.Namespace); labels != "" {
			evidence = append(evidence, FieldEvidence("labels actually present on pods in the namespace", labels))
		}
		steps = []string{
			fmt.Sprintf("kubectl -n %s get pods --show-labels", svc.Namespace),
			fmt.Sprintf("kubectl -n %s get endpointslice -l %s=%s", svc.Namespace, discoveryv1.LabelServiceName, svc.Name),
		}

	default:
		title = "Service has endpoints but none is ready"
		summary = fmt.Sprintf(
			"%d pod(s) match the selector, so the labels are right, but not one of them is ready — "+
				"Kubernetes therefore routes to none of them. The Service is not the problem here; the "+
				"pods behind it are, and the findings about those pods explain why. This entry exists "+
				"because the symptom people report is \"the service is down\", and this is the link "+
				"between that sentence and the pod that caused it.",
			len(matching))
		evidence = append(evidence, FieldEvidence("pods matching the selector", matchingPodSummary(matching)))
		steps = []string{
			fmt.Sprintf("kubectl -n %s get pods -l %s", svc.Namespace, selector),
			fmt.Sprintf("kubectl -n %s get endpointslice -l %s=%s -o yaml", svc.Namespace, discoveryv1.LabelServiceName, svc.Name),
		}
	}

	if mismatch := portMismatch(svc, matching); mismatch != "" {
		summary += " " + mismatch
		evidence = append(evidence, FieldEvidence("spec.ports[*].targetPort", servicePortSummary(svc)))
	}

	return Finding{
		Title:     title,
		Severity:  SeverityCritical,
		Subject:   ObjectRef{Kind: "Service", Namespace: svc.Namespace, Name: svc.Name},
		Summary:   summary,
		Evidence:  evidence,
		NextSteps: steps,
	}
}

func formatSelector(sel map[string]string) string {
	if len(sel) == 0 {
		return "none"
	}
	keys := make([]string, 0, len(sel))
	for k := range sel {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+sel[k])
	}
	return strings.Join(parts, ",")
}

func podsInNamespace(s *snapshot.Snapshot, namespace string) int {
	n := 0
	for i := range s.Pods {
		if s.Pods[i].Namespace == namespace {
			n++
		}
	}
	return n
}

// podLabelSample lists the distinct label sets in the namespace so a reader can
// spot the typo without a second command.
func podLabelSample(s *snapshot.Snapshot, namespace string) string {
	seen := map[string]bool{}
	var out []string
	for i := range s.Pods {
		if s.Pods[i].Namespace != namespace {
			continue
		}
		set := formatSelector(withoutGeneratedLabels(s.Pods[i].Labels))
		if set != "none" && !seen[set] {
			seen[set] = true
			out = append(out, set)
		}
	}
	sort.Strings(out)
	if len(out) > 5 {
		out = out[:5]
	}
	return strings.Join(out, " | ")
}

// withoutGeneratedLabels drops the labels controllers add, which are noise when
// the reader is comparing a selector against what they wrote.
func withoutGeneratedLabels(labels map[string]string) map[string]string {
	out := make(map[string]string, len(labels))
	for k, v := range labels {
		switch k {
		case "pod-template-hash", "controller-revision-hash", "statefulset.kubernetes.io/pod-name", "batch.kubernetes.io/job-name", "job-name":
			continue
		}
		out[k] = v
	}
	return out
}

func matchingPodSummary(pods []corev1.Pod) string {
	parts := make([]string, 0, len(pods))
	for i := range pods {
		p := &pods[i]
		state := string(p.Status.Phase)
		if c := snapshot.PodCondition(p, corev1.PodReady); c != nil && c.Status != corev1.ConditionTrue {
			state += "/not ready"
			if c.Reason != "" {
				state += " (" + c.Reason + ")"
			}
		}
		parts = append(parts, p.Name+": "+state)
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
}

// portMismatch catches the case where the labels line up and the pods are ready
// but the Service points at a port no container declares. Kubernetes does not
// validate this: targetPort is free-form and a name that matches nothing simply
// produces no endpoint.
func portMismatch(svc *corev1.Service, pods []corev1.Pod) string {
	if len(pods) == 0 {
		return ""
	}
	declared := map[string]bool{}
	for i := range pods {
		for _, c := range pods[i].Spec.Containers {
			for _, p := range c.Ports {
				declared[fmt.Sprintf("%d", p.ContainerPort)] = true
				if p.Name != "" {
					declared[p.Name] = true
				}
			}
		}
	}
	var missing []string
	for _, sp := range svc.Spec.Ports {
		target := sp.TargetPort.String()
		if target == "0" || target == "" {
			target = fmt.Sprintf("%d", sp.Port)
		}
		if !declared[target] {
			missing = append(missing, target)
		}
	}
	if len(missing) == 0 {
		return ""
	}
	sort.Strings(missing)
	return fmt.Sprintf("Separately, the Service targets port(s) %s and no container in the matching "+
		"pods declares them; a named targetPort that matches no containerPort name produces no "+
		"endpoint at all, silently.", strings.Join(missing, ", "))
}

func servicePortSummary(svc *corev1.Service) string {
	parts := make([]string, 0, len(svc.Spec.Ports))
	for _, p := range svc.Spec.Ports {
		parts = append(parts, fmt.Sprintf("%d -> %s", p.Port, p.TargetPort.String()))
	}
	return strings.Join(parts, ", ")
}
