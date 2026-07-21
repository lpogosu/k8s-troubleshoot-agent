package rules

import (
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"

	"github.com/lpogosu/k8s-troubleshoot-agent/internal/snapshot"
)

// quotaExhaustionThreshold is the fraction of a quota at which the rule starts
// warning. Below full it is not yet an outage, but a namespace at 90% of its
// pod count cannot survive a rolling update, which needs headroom for the new
// replica before the old one goes away.
const quotaExhaustionThreshold = 0.9

// quotaRule reports a ResourceQuota that is blocking, or about to block,
// object creation.
//
// The failure this catches is deliberately indirect. A quota does not make an
// existing pod unhealthy — it makes new ones fail to be created, and the error
// lands on the ReplicaSet, not on any pod. `kubectl get pods` shows fewer
// replicas than expected and nothing else, which is why a namespace can sit at
// half capacity for days without anyone noticing.
type quotaRule struct{}

func (quotaRule) ID() string { return "KTA008" }

func (quotaRule) Description() string {
	return "ResourceQuota is exhausted, so new pods in the namespace are rejected at admission"
}

func (r quotaRule) Evaluate(s *snapshot.Snapshot) []Finding {
	var out []Finding
	for i := range s.ResourceQuotas {
		quota := &s.ResourceQuotas[i]
		if snapshot.Terminating(&quota.ObjectMeta) {
			continue
		}
		exhausted, tight := splitByPressure(quota)
		if len(exhausted) == 0 && len(tight) == 0 {
			continue
		}
		out = append(out, r.finding(s, quota, exhausted, tight))
	}
	return out
}

// quotaUsage is one resource line of a quota.
type quotaUsage struct {
	name     corev1.ResourceName
	used     resource.Quantity
	hard     resource.Quantity
	fraction float64
}

func (u quotaUsage) String() string {
	return fmt.Sprintf("%s used=%s hard=%s (%.0f%%)", u.name, u.used.String(), u.hard.String(), u.fraction*100)
}

// splitByPressure separates resources that are completely used up from those
// that are merely close to it. The two carry different severities because only
// the first is already rejecting objects.
func splitByPressure(quota *corev1.ResourceQuota) (exhausted, tight []quotaUsage) {
	names := make([]string, 0, len(quota.Status.Hard))
	for name := range quota.Status.Hard {
		names = append(names, string(name))
	}
	sort.Strings(names)

	for _, n := range names {
		name := corev1.ResourceName(n)
		hard := quota.Status.Hard[name]
		used, ok := quota.Status.Used[name]
		if !ok || hard.IsZero() {
			continue
		}
		fraction := quantityRatio(used, hard)
		u := quotaUsage{name: name, used: used, hard: hard, fraction: fraction}
		switch {
		case used.Cmp(hard) >= 0:
			exhausted = append(exhausted, u)
		case fraction >= quotaExhaustionThreshold:
			tight = append(tight, u)
		}
	}
	return exhausted, tight
}

// quantityRatio divides two quantities via their scaled integer values.
// Quantity has no division, and converting through float64 at full precision
// would overflow on memory values expressed in bytes, so both sides are scaled
// to milli-units first — that keeps 1Gi comfortably inside int64.
func quantityRatio(used, hard resource.Quantity) float64 {
	h := hard.MilliValue()
	if h == 0 {
		return 0
	}
	return float64(used.MilliValue()) / float64(h)
}

func (r quotaRule) finding(
	s *snapshot.Snapshot,
	quota *corev1.ResourceQuota,
	exhausted, tight []quotaUsage,
) Finding {
	evidence := make([]Evidence, 0, len(exhausted)+len(tight)+1)
	for _, u := range exhausted {
		evidence = append(evidence, FieldEvidence("status.used["+string(u.name)+"]", u.String()))
	}
	for _, u := range tight {
		evidence = append(evidence, FieldEvidence("status.used["+string(u.name)+"]", u.String()))
	}

	// The admission rejection surfaces on the controller, not on a pod: a
	// ReplicaSet that cannot create its pod records FailedCreate and keeps
	// trying. Quoting it turns an abstract percentage into a real symptom.
	if e := snapshot.LatestEvent(quotaRelatedEvents(s, quota.Namespace), "FailedCreate"); e != nil {
		evidence = append(evidence, EventEvidence(e))
	}

	severity := SeverityWarning
	title := fmt.Sprintf("ResourceQuota %s is nearly exhausted", quota.Name)
	summary := fmt.Sprintf(
		"Namespace %s is above %.0f%% of its quota for %s. Nothing is failing yet, but there is no "+
			"room left for a rolling update: a Deployment with maxSurge above zero needs to create the "+
			"new pod before removing the old one, and that creation will be rejected.",
		quota.Namespace, quotaExhaustionThreshold*100, usageNames(tight))

	if len(exhausted) > 0 {
		severity = SeverityCritical
		title = fmt.Sprintf("ResourceQuota %s is exhausted", quota.Name)
		summary = fmt.Sprintf(
			"Namespace %s has spent its entire quota for %s, so the API server now rejects new objects "+
				"at admission. This does not show up on any pod — the pod is never created. The error "+
				"lands on whatever tried to create it, usually a ReplicaSet, and the only visible symptom "+
				"is a Deployment that stays below its desired replica count.",
			quota.Namespace, usageNames(exhausted))
		if hasComputeResource(exhausted) {
			summary += " Note that compute quotas count *requests and limits declared in the pod spec*, " +
				"not consumption: a namespace can be at 100% of its CPU quota with every pod idle."
		}
	}

	if len(quota.Spec.Scopes) > 0 || quota.Spec.ScopeSelector != nil {
		evidence = append(evidence, FieldEvidence("spec.scopes", scopeSummary(quota)))
	}

	return Finding{
		Title:    title,
		Severity: severity,
		Subject:  ObjectRef{Kind: "ResourceQuota", Namespace: quota.Namespace, Name: quota.Name},
		Summary:  summary,
		Evidence: evidence,
		NextSteps: []string{
			describeCmd("resourcequota", quota.Namespace, quota.Name),
			fmt.Sprintf("kubectl -n %s get events --field-selector reason=FailedCreate", quota.Namespace),
		},
	}
}

// quotaRelatedEvents returns the namespace's events from objects that create
// pods, where a quota rejection actually lands.
func quotaRelatedEvents(s *snapshot.Snapshot, namespace string) []corev1.Event {
	var out []corev1.Event
	for _, e := range s.Events {
		if e.Namespace != namespace {
			continue
		}
		switch e.InvolvedObject.Kind {
		case "ReplicaSet", "StatefulSet", "DaemonSet", "Job", "Deployment":
			out = append(out, e)
		}
	}
	return out
}

func usageNames(usages []quotaUsage) string {
	names := make([]string, 0, len(usages))
	for _, u := range usages {
		names = append(names, string(u.name))
	}
	return strings.Join(names, ", ")
}

func hasComputeResource(usages []quotaUsage) bool {
	for _, u := range usages {
		if strings.Contains(string(u.name), "cpu") || strings.Contains(string(u.name), "memory") {
			return true
		}
	}
	return false
}

func scopeSummary(quota *corev1.ResourceQuota) string {
	parts := make([]string, 0, len(quota.Spec.Scopes))
	for _, s := range quota.Spec.Scopes {
		parts = append(parts, string(s))
	}
	if quota.Spec.ScopeSelector != nil {
		for _, e := range quota.Spec.ScopeSelector.MatchExpressions {
			parts = append(parts, fmt.Sprintf("%s %s %v", e.ScopeName, e.Operator, e.Values))
		}
	}
	return strings.Join(parts, ", ")
}
