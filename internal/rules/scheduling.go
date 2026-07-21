package rules

import (
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"

	"github.com/lpogosu/k8s-troubleshoot-agent/internal/snapshot"
)

// unschedulableRule explains why a pod is stuck in Pending.
//
// The scheduler already writes a precise reason into the PodScheduled
// condition — "0/3 nodes are available: 1 Insufficient cpu, 2 node(s) had
// untolerated taint {node-role.kubernetes.io/control-plane: }". The problem is
// that this sentence conflates several independent reasons and expresses them
// as counts, so a reader has to reconstruct which of them actually blocks
// *their* pod. This rule splits it apart and, where the snapshot has the
// objects, checks the claim against the cluster instead of only quoting it.
type unschedulableRule struct{}

func (unschedulableRule) ID() string { return "KTA003" }

func (unschedulableRule) Description() string {
	return "pod stays Pending: insufficient resources, taints, node selector or unbound volume"
}

func (r unschedulableRule) Evaluate(s *snapshot.Snapshot) []Finding {
	var out []Finding
	for i := range s.Pods {
		pod := &s.Pods[i]
		if !diagnosable(pod) || pod.Status.Phase != corev1.PodPending || pod.Spec.NodeName != "" {
			continue
		}
		cond := snapshot.PodCondition(pod, corev1.PodScheduled)
		// No condition yet means the scheduler has not looked at the pod. That
		// is the normal state for the first second of a pod's life.
		if cond == nil || cond.Status == corev1.ConditionTrue {
			continue
		}
		out = append(out, r.finding(s, pod, cond))
	}
	return out
}

func (r unschedulableRule) finding(s *snapshot.Snapshot, pod *corev1.Pod, cond *corev1.PodCondition) Finding {
	evidence := []Evidence{
		ConditionEvidence("status.conditions[type=PodScheduled]", "PodScheduled",
			string(cond.Status), cond.Reason, cond.Message),
	}
	if e := snapshot.LatestEvent(s.EventsFor("Pod", pod.Namespace, pod.Name), "FailedScheduling"); e != nil {
		evidence = append(evidence, EventEvidence(e))
	}

	reasons := classifyScheduling(cond.Message)
	summary, extraEvidence, steps := r.explain(s, pod, reasons)
	evidence = append(evidence, extraEvidence...)

	// A pod nobody can place is critical; one whose scheduling is merely slow
	// is not, and the difference is whether the scheduler gave a reason it
	// considers permanent.
	severity := SeverityCritical
	if len(reasons) == 0 && s.Age(pod.Status.StartTime) < StartupGrace {
		severity = SeverityWarning
	}

	return Finding{
		Title:     schedulingTitle(reasons),
		Severity:  severity,
		Subject:   podRef(pod, ""),
		Summary:   summary + ownerHint(pod),
		Evidence:  evidence,
		NextSteps: steps,
	}
}

// schedulingReason enumerates the blockers the scheduler reports. They are
// deliberately coarse: each maps to a different person fixing a different file.
type schedulingReason string

const (
	reasonInsufficientCPU    schedulingReason = "insufficient-cpu"
	reasonInsufficientMemory schedulingReason = "insufficient-memory"
	reasonOtherResource      schedulingReason = "insufficient-other"
	reasonTaint              schedulingReason = "untolerated-taint"
	reasonNodeSelector       schedulingReason = "node-selector"
	reasonUnboundVolume      schedulingReason = "unbound-volume"
	reasonVolumeAffinity     schedulingReason = "volume-node-affinity"
	reasonAffinityRules      schedulingReason = "pod-affinity"
	reasonNoNodes            schedulingReason = "no-nodes"
)

// classifyScheduling extracts every blocker named in the scheduler's message.
// More than one can be present, and reporting only the first hides the fact
// that fixing it will not be enough.
func classifyScheduling(msg string) []schedulingReason {
	checks := []struct {
		reason   schedulingReason
		patterns []string
	}{
		{reasonInsufficientCPU, []string{"insufficient cpu"}},
		{reasonInsufficientMemory, []string{"insufficient memory", "insufficient ephemeral-storage"}},
		{reasonOtherResource, []string{"insufficient nvidia.com/gpu", "insufficient pods"}},
		{reasonTaint, []string{"untolerated taint", "had taint", "node(s) had taints"}},
		{reasonNodeSelector, []string{"didn't match pod's node affinity/selector", "didn't match node selector"}},
		{reasonUnboundVolume, []string{"unbound immediate persistentvolumeclaims", "pod has unbound"}},
		{reasonVolumeAffinity, []string{"volume node affinity conflict"}},
		{reasonAffinityRules, []string{"didn't match pod affinity", "didn't match pod anti-affinity", "didn't satisfy existing pods anti-affinity"}},
		{reasonNoNodes, []string{"no nodes available"}},
	}
	var out []schedulingReason
	for _, c := range checks {
		if snapshot.MessageMatchesAny(msg, c.patterns...) {
			out = append(out, c.reason)
		}
	}
	return out
}

func schedulingTitle(reasons []schedulingReason) string {
	if len(reasons) == 0 {
		return "pod cannot be scheduled"
	}
	titles := map[schedulingReason]string{
		reasonInsufficientCPU:    "no node has enough free CPU",
		reasonInsufficientMemory: "no node has enough free memory",
		reasonOtherResource:      "no node has enough of a requested resource",
		reasonTaint:              "every candidate node carries a taint the pod does not tolerate",
		reasonNodeSelector:       "no node matches the pod's node selector",
		reasonUnboundVolume:      "pod is waiting for a PersistentVolumeClaim to bind",
		reasonVolumeAffinity:     "the pod's volume is pinned to a node that cannot take the pod",
		reasonAffinityRules:      "pod affinity rules exclude every node",
		reasonNoNodes:            "the cluster has no schedulable node",
	}
	parts := make([]string, 0, len(reasons))
	for _, r := range reasons {
		parts = append(parts, titles[r])
	}
	return strings.Join(parts, "; ")
}

func (r unschedulableRule) explain(
	s *snapshot.Snapshot,
	pod *corev1.Pod,
	reasons []schedulingReason,
) (summary string, evidence []Evidence, steps []string) {
	var parts []string
	steps = []string{describeCmd("pod", pod.Namespace, pod.Name)}

	has := func(want schedulingReason) bool {
		for _, r := range reasons {
			if r == want {
				return true
			}
		}
		return false
	}

	if has(reasonInsufficientCPU) || has(reasonInsufficientMemory) || has(reasonOtherResource) {
		req := totalRequests(pod)
		parts = append(parts, fmt.Sprintf(
			"The pod asks for %s and no node has that much unreserved. Note that the scheduler compares "+
				"against the sum of *requests* already placed on each node, not against current usage — a "+
				"node can be idle and still be full.", req))
		evidence = append(evidence, FieldEvidence("spec.containers[*].resources.requests", req))
		evidence = append(evidence, nodeAllocatableEvidence(s)...)
		steps = append(steps,
			"kubectl describe nodes | grep -A5 'Allocated resources'",
			fmt.Sprintf("kubectl -n %s get pod %s -o jsonpath='{.spec.containers[*].resources.requests}'", pod.Namespace, pod.Name),
		)
	}

	if has(reasonTaint) {
		taints := taintInventory(s)
		detail := "the snapshot contains no nodes, so the taints cannot be listed"
		if len(taints) > 0 {
			detail = strings.Join(taints, "; ")
			evidence = append(evidence, FieldEvidence("nodes[*].spec.taints", detail))
		}
		parts = append(parts, fmt.Sprintf(
			"Every node the scheduler considered is tainted against this pod. Taints present in the "+
				"cluster: %s. Either add a matching toleration to the pod template, or remove the taint "+
				"from the nodes that should accept the workload — a taint is the node saying no, so "+
				"adding capacity will not help.", detail))
		evidence = append(evidence, FieldEvidence("spec.tolerations", tolerationSummary(pod)))
		steps = append(steps, "kubectl get nodes -o custom-columns=NAME:.metadata.name,TAINTS:.spec.taints")
	}

	if has(reasonNodeSelector) {
		sel := selectorSummary(pod)
		parts = append(parts, fmt.Sprintf(
			"The pod restricts itself to nodes matching %s and no node in the cluster carries those "+
				"labels. The usual causes are a label that was renamed, a typo, or a manifest copied from "+
				"a cluster whose nodes were labelled differently.", sel))
		evidence = append(evidence,
			FieldEvidence("spec.nodeSelector", sel),
			FieldEvidence("nodes[*].metadata.labels", nodeLabelSample(s)),
		)
		steps = append(steps, "kubectl get nodes --show-labels")
	}

	if has(reasonUnboundVolume) || has(reasonVolumeAffinity) {
		names := claimNames(pod)
		parts = append(parts, fmt.Sprintf(
			"The pod cannot start until its volume is available: %s. The scheduler will not place the "+
				"pod anywhere while the claim is unbound, so the pod's own resources and tolerations are "+
				"irrelevant until the storage side is resolved.", names))
		evidence = append(evidence, FieldEvidence("spec.volumes[*].persistentVolumeClaim", names))
		for _, name := range pvcNames(pod) {
			if claim := s.PVC(pod.Namespace, name); claim != nil {
				evidence = append(evidence, FieldEvidence(
					fmt.Sprintf("PersistentVolumeClaim/%s/%s.status.phase", pod.Namespace, name),
					string(claim.Status.Phase),
				))
			}
		}
		steps = append(steps, fmt.Sprintf("kubectl -n %s get pvc", pod.Namespace))
	}

	if has(reasonAffinityRules) {
		parts = append(parts, "The pod's affinity or anti-affinity rules exclude every node. Anti-affinity "+
			"with topologyKey kubernetes.io/hostname and more replicas than nodes is the classic version "+
			"of this: the last replicas have nowhere left to go and stay Pending indefinitely.")
		evidence = append(evidence, FieldEvidence("spec.affinity", affinitySummary(pod)))
	}

	if has(reasonNoNodes) || len(s.Nodes) == 0 && s.ClusterWide() {
		parts = append(parts, "The scheduler found no node it could even consider. Check that nodes exist "+
			"and are Ready, and that they are not cordoned.")
		steps = append(steps, "kubectl get nodes")
	}

	if len(parts) == 0 {
		parts = append(parts, "The scheduler rejected every node but its message does not match any "+
			"pattern this tool knows, so the condition message above is the diagnosis and this summary "+
			"adds nothing to it.")
	}

	return strings.Join(parts, " "), evidence, steps
}

func totalRequests(pod *corev1.Pod) string {
	total := corev1.ResourceList{}
	add := func(list corev1.ResourceList) {
		for name, q := range list {
			if cur, ok := total[name]; ok {
				cur.Add(q)
				total[name] = cur
			} else {
				total[name] = q.DeepCopy()
			}
		}
	}
	for i := range pod.Spec.Containers {
		add(pod.Spec.Containers[i].Resources.Requests)
	}
	// Init containers do not add to the running total; the scheduler takes the
	// maximum of any single init container against the sum of the rest.
	for i := range pod.Spec.InitContainers {
		for name, q := range pod.Spec.InitContainers[i].Resources.Requests {
			if cur, ok := total[name]; !ok || q.Cmp(cur) > 0 {
				total[name] = q.DeepCopy()
			}
		}
	}
	return formatResourceList(total)
}

func formatResourceList(list corev1.ResourceList) string {
	if len(list) == 0 {
		return "no resource requests"
	}
	names := make([]string, 0, len(list))
	for n := range list {
		names = append(names, string(n))
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, n := range names {
		q := list[corev1.ResourceName(n)]
		parts = append(parts, n+"="+q.String())
	}
	return strings.Join(parts, " ")
}

// nodeAllocatableEvidence reports what the cluster actually has, so the reader
// can see at a glance whether the request is merely unlucky or impossible.
func nodeAllocatableEvidence(s *snapshot.Snapshot) []Evidence {
	if len(s.Nodes) == 0 {
		return nil
	}
	var lines []string
	for i := range s.Nodes {
		n := &s.Nodes[i]
		cpu := n.Status.Allocatable[corev1.ResourceCPU]
		mem := n.Status.Allocatable[corev1.ResourceMemory]
		line := fmt.Sprintf("%s allocatable cpu=%s memory=%s", n.Name, quantityString(cpu), quantityString(mem))
		if n.Spec.Unschedulable {
			line += " (cordoned)"
		}
		lines = append(lines, line)
	}
	sort.Strings(lines)
	return []Evidence{FieldEvidence("nodes[*].status.allocatable", strings.Join(lines, "; "))}
}

func quantityString(q resource.Quantity) string { return q.String() }

func taintInventory(s *snapshot.Snapshot) []string {
	seen := map[string]bool{}
	var out []string
	for i := range s.Nodes {
		for _, t := range s.Nodes[i].Spec.Taints {
			key := fmt.Sprintf("%s=%s:%s", t.Key, t.Value, t.Effect)
			if !seen[key] {
				seen[key] = true
				out = append(out, key)
			}
		}
	}
	sort.Strings(out)
	return out
}

func tolerationSummary(pod *corev1.Pod) string {
	if len(pod.Spec.Tolerations) == 0 {
		return "none"
	}
	parts := make([]string, 0, len(pod.Spec.Tolerations))
	for _, t := range pod.Spec.Tolerations {
		switch {
		case t.Operator == corev1.TolerationOpExists && t.Key == "":
			parts = append(parts, "tolerates everything")
		case t.Operator == corev1.TolerationOpExists:
			parts = append(parts, t.Key+" exists")
		default:
			parts = append(parts, fmt.Sprintf("%s=%s:%s", t.Key, t.Value, t.Effect))
		}
	}
	sort.Strings(parts)
	return strings.Join(parts, ", ")
}

func selectorSummary(pod *corev1.Pod) string {
	if len(pod.Spec.NodeSelector) == 0 {
		return "node affinity rules (spec.affinity.nodeAffinity)"
	}
	keys := make([]string, 0, len(pod.Spec.NodeSelector))
	for k := range pod.Spec.NodeSelector {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+pod.Spec.NodeSelector[k])
	}
	return strings.Join(parts, ",")
}

// nodeLabelSample lists the values nodes actually carry for the label keys that
// commonly appear in node selectors. Dumping every label would bury the answer.
func nodeLabelSample(s *snapshot.Snapshot) string {
	interesting := []string{
		"kubernetes.io/os", "kubernetes.io/arch", "node.kubernetes.io/instance-type",
		"topology.kubernetes.io/zone", "node-role.kubernetes.io/worker",
	}
	var lines []string
	for i := range s.Nodes {
		n := &s.Nodes[i]
		var kv []string
		for _, k := range interesting {
			if v, ok := n.Labels[k]; ok {
				kv = append(kv, k+"="+v)
			}
		}
		lines = append(lines, fmt.Sprintf("%s: %s", n.Name, strings.Join(kv, ",")))
	}
	if len(lines) == 0 {
		return "no nodes in snapshot"
	}
	sort.Strings(lines)
	return strings.Join(lines, "; ")
}

func pvcNames(pod *corev1.Pod) []string {
	var out []string
	for _, v := range pod.Spec.Volumes {
		if v.PersistentVolumeClaim != nil {
			out = append(out, v.PersistentVolumeClaim.ClaimName)
		}
	}
	sort.Strings(out)
	return out
}

func claimNames(pod *corev1.Pod) string {
	names := pvcNames(pod)
	if len(names) == 0 {
		return "a volume that is not a PersistentVolumeClaim"
	}
	return "PersistentVolumeClaim " + strings.Join(names, ", ")
}

func affinitySummary(pod *corev1.Pod) string {
	a := pod.Spec.Affinity
	if a == nil {
		return "not set"
	}
	var parts []string
	if a.NodeAffinity != nil {
		parts = append(parts, "nodeAffinity")
	}
	if a.PodAffinity != nil {
		parts = append(parts, "podAffinity")
	}
	if a.PodAntiAffinity != nil {
		parts = append(parts, "podAntiAffinity")
		for _, term := range a.PodAntiAffinity.RequiredDuringSchedulingIgnoredDuringExecution {
			parts = append(parts, "required anti-affinity topologyKey="+term.TopologyKey)
		}
	}
	return strings.Join(parts, ", ")
}
