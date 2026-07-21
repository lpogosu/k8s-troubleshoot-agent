package rules

import (
	"fmt"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/lpogosu/k8s-troubleshoot-agent/internal/snapshot"
)

// nodeHealthRule reports nodes that cannot host workloads.
//
// It is placed above the pod rules in importance for a practical reason: one
// NotReady node produces a page of pod-level findings that all have the same
// cause, and a reader who fixes pods first wastes the outage. The rule
// therefore names the pods that are stranded on the node, turning a list of
// symptoms into one cause.
type nodeHealthRule struct{}

func (nodeHealthRule) ID() string { return "KTA009" }

func (nodeHealthRule) Description() string {
	return "node is NotReady, under disk or memory pressure, or cordoned"
}

func (r nodeHealthRule) Evaluate(s *snapshot.Snapshot) []Finding {
	var out []Finding
	for i := range s.Nodes {
		node := &s.Nodes[i]
		if snapshot.Terminating(&node.ObjectMeta) {
			continue
		}
		if f, ok := r.readiness(s, node); ok {
			out = append(out, f)
		}
		out = append(out, r.pressure(s, node)...)
		if f, ok := r.cordoned(node); ok {
			out = append(out, f)
		}
	}
	return out
}

func (r nodeHealthRule) readiness(s *snapshot.Snapshot, node *corev1.Node) (Finding, bool) {
	ready := snapshot.NodeCondition(node, corev1.NodeReady)
	if ready == nil || ready.Status == corev1.ConditionTrue {
		return Finding{}, false
	}

	evidence := []Evidence{
		ConditionEvidence("status.conditions[type=Ready]", "Ready",
			string(ready.Status), ready.Reason, ready.Message),
		FieldEvidence("status.conditions[type=Ready].lastHeartbeatTime",
			fmt.Sprintf("%s (%s before capture)",
				snapshot.FormatTime(ready.LastHeartbeatTime),
				s.Age(&ready.LastHeartbeatTime).Round(time.Second))),
	}

	stranded := podsOn(s, node.Name)
	if len(stranded) > 0 {
		evidence = append(evidence, FieldEvidence("pods scheduled on this node", strings.Join(stranded, ", ")))
	}

	summary := "The node has stopped reporting itself as healthy."
	if ready.Status == corev1.ConditionUnknown {
		summary += " The condition is Unknown rather than False, which specifically means the control " +
			"plane stopped hearing from the kubelet altogether — the node may well be running fine and " +
			"simply unable to reach the API server. Network, not workload."
	} else {
		summary += " The kubelet is reachable and is reporting a problem of its own, so the message " +
			"above comes from the node itself rather than from a timeout."
	}
	summary += fmt.Sprintf(" %d pod(s) are scheduled here; after the eviction timeout the controller "+
		"manager will start recreating the ones that belong to a controller, and any pod holding a "+
		"ReadWriteOnce volume will block until its old attachment is released.", len(stranded))

	return Finding{
		Title:    "node is not Ready",
		Severity: SeverityCritical,
		Subject:  ObjectRef{Kind: "Node", Name: node.Name},
		Summary:  summary,
		Evidence: evidence,
		NextSteps: []string{
			"kubectl describe node " + node.Name,
			"kubectl get pods -A -o wide --field-selector spec.nodeName=" + node.Name,
		},
	}, true
}

// pressureCondition describes one of the kubelet's resource-pressure signals.
type pressureCondition struct {
	condition corev1.NodeConditionType
	title     string
	summary   string
	step      string
}

var pressureConditions = []pressureCondition{
	{
		condition: corev1.NodeDiskPressure,
		title:     "node is under disk pressure",
		summary: "The kubelet has crossed its eviction threshold for disk and is now garbage-collecting " +
			"images and evicting pods to reclaim space. Two things follow that are easy to misread: image " +
			"pulls on this node start failing with no space left, and pods disappear with reason Evicted " +
			"rather than crashing. Container logs and emptyDir volumes share this filesystem, so a single " +
			"chatty workload can take the node down for everyone on it.",
		step: "kubectl describe node {node} | grep -A10 Conditions",
	},
	{
		condition: corev1.NodeMemoryPressure,
		title:     "node is under memory pressure",
		summary: "Available memory on the node has fallen below the kubelet's eviction threshold. The " +
			"kubelet evicts pods in QoS order — BestEffort first, then Burstable that exceed their " +
			"requests — so the workloads that go down are chosen by their resource declarations rather " +
			"than by their importance. Pods without requests are the first to be sacrificed.",
		step: "kubectl top nodes",
	},
	{
		condition: corev1.NodePIDPressure,
		title:     "node is running out of process IDs",
		summary: "The node is close to its PID limit. This is almost always one container forking " +
			"without reaping, and it degrades everything on the node rather than only the offender, " +
			"because new processes anywhere on the host start failing.",
		step: "kubectl describe node {node}",
	},
}

func (r nodeHealthRule) pressure(s *snapshot.Snapshot, node *corev1.Node) []Finding {
	var out []Finding
	for _, pc := range pressureConditions {
		cond := snapshot.NodeCondition(node, pc.condition)
		if cond == nil || cond.Status != corev1.ConditionTrue {
			continue
		}
		evidence := []Evidence{
			ConditionEvidence("status.conditions[type="+string(pc.condition)+"]",
				string(pc.condition), string(cond.Status), cond.Reason, cond.Message),
		}
		if pc.condition == corev1.NodeDiskPressure {
			if e := allocatableEvidence(node, corev1.ResourceEphemeralStorage); e != nil {
				evidence = append(evidence, *e)
			}
		}
		if pc.condition == corev1.NodeMemoryPressure {
			if e := allocatableEvidence(node, corev1.ResourceMemory); e != nil {
				evidence = append(evidence, *e)
			}
		}
		if evicted := evictedPods(s, node.Name); evicted != "" {
			evidence = append(evidence, FieldEvidence("pods evicted from this node", evicted))
		}
		out = append(out, Finding{
			Title:     pc.title,
			Severity:  SeverityWarning,
			Subject:   ObjectRef{Kind: "Node", Name: node.Name},
			Summary:   pc.summary,
			Evidence:  evidence,
			NextSteps: []string{strings.ReplaceAll(pc.step, "{node}", node.Name)},
		})
	}
	return out
}

func (r nodeHealthRule) cordoned(node *corev1.Node) (Finding, bool) {
	if !node.Spec.Unschedulable {
		return Finding{}, false
	}
	// A cordoned node is usually deliberate, so this is informational — it is
	// here because it silently removes capacity, and a Pending pod on a
	// cluster whose spare node is cordoned is otherwise baffling.
	evidence := []Evidence{FieldEvidence("spec.unschedulable", "true")}
	if len(node.Spec.Taints) > 0 {
		evidence = append(evidence, FieldEvidence("spec.taints", taintList(node)))
	}
	return Finding{
		Title:    "node is cordoned",
		Severity: SeverityInfo,
		Subject:  ObjectRef{Kind: "Node", Name: node.Name},
		Summary: "The node is marked unschedulable, so the scheduler will not place new pods on it " +
			"while existing pods keep running. This is normal during maintenance; it matters here " +
			"because the capacity it removes is invisible in `kubectl get nodes`, which still shows " +
			"the node as Ready.",
		Evidence:  evidence,
		NextSteps: []string{"kubectl uncordon " + node.Name + "   # when maintenance is finished"},
	}, true
}

func allocatableEvidence(node *corev1.Node, name corev1.ResourceName) *Evidence {
	q, ok := node.Status.Allocatable[name]
	if !ok {
		return nil
	}
	e := FieldEvidence("status.allocatable["+string(name)+"]", q.String())
	return &e
}

func podsOn(s *snapshot.Snapshot, node string) []string {
	var out []string
	for i := range s.Pods {
		p := &s.Pods[i]
		if p.Spec.NodeName == node {
			out = append(out, p.Namespace+"/"+p.Name)
		}
	}
	sort.Strings(out)
	return out
}

func evictedPods(s *snapshot.Snapshot, node string) string {
	var out []string
	for i := range s.Pods {
		p := &s.Pods[i]
		if p.Spec.NodeName == node && p.Status.Reason == "Evicted" {
			out = append(out, p.Namespace+"/"+p.Name)
		}
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

func taintList(node *corev1.Node) string {
	parts := make([]string, 0, len(node.Spec.Taints))
	for _, t := range node.Spec.Taints {
		parts = append(parts, fmt.Sprintf("%s=%s:%s", t.Key, t.Value, t.Effect))
	}
	sort.Strings(parts)
	return strings.Join(parts, ", ")
}
