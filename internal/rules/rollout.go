package rules

import (
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/lpogosu/k8s-troubleshoot-agent/internal/snapshot"
)

// rolloutRule reports a Deployment or StatefulSet that is not converging.
//
// The pod rules explain individual failures; this one answers the question the
// operator actually asked, which is "is my release out?". It is also the only
// rule that catches a rollout blocked with *zero* unhealthy pods — a Deployment
// whose new ReplicaSet cannot create anything at all (quota, admission webhook,
// missing service account) has no broken pod to point at, because no pod exists.
type rolloutRule struct{}

func (rolloutRule) ID() string { return "KTA010" }

func (rolloutRule) Description() string {
	return "Deployment or StatefulSet has fewer available replicas than desired"
}

func (r rolloutRule) Evaluate(s *snapshot.Snapshot) []Finding {
	var out []Finding
	for i := range s.Deployments {
		if f, ok := r.deployment(s, &s.Deployments[i]); ok {
			out = append(out, f)
		}
	}
	for i := range s.StatefulSets {
		if f, ok := r.statefulSet(s, &s.StatefulSets[i]); ok {
			out = append(out, f)
		}
	}
	return out
}

func (r rolloutRule) deployment(s *snapshot.Snapshot, d *appsv1.Deployment) (Finding, bool) {
	if snapshot.Terminating(&d.ObjectMeta) {
		return Finding{}, false
	}
	desired := int32(1)
	if d.Spec.Replicas != nil {
		desired = *d.Spec.Replicas
	}
	// Scaled to zero on purpose is not a fault.
	if desired == 0 || d.Status.AvailableReplicas >= desired {
		return Finding{}, false
	}
	// A rollout that started seconds ago is expected to be short of replicas.
	if s.Age(&d.CreationTimestamp) < StartupGrace {
		return Finding{}, false
	}

	evidence := []Evidence{
		FieldEvidence("spec.replicas", fmt.Sprintf("%d", desired)),
		FieldEvidence("status", fmt.Sprintf("ready=%d available=%d updated=%d unavailable=%d",
			d.Status.ReadyReplicas, d.Status.AvailableReplicas, d.Status.UpdatedReplicas, d.Status.UnavailableReplicas)),
	}

	summary := fmt.Sprintf(
		"%d of %d replicas are available. Deployments do not surface the reason on themselves — the "+
			"reason lives on the pods, or on the ReplicaSet when no pod could be created at all.",
		d.Status.AvailableReplicas, desired)
	severity := SeverityWarning
	if d.Status.AvailableReplicas == 0 {
		severity = SeverityCritical
		summary = fmt.Sprintf(
			"No replica of this Deployment is available: %d were asked for and none is serving. The "+
				"workload is fully down, not degraded.", desired)
	}

	if prog := deploymentCondition(d, appsv1.DeploymentProgressing); prog != nil && prog.Status == corev1.ConditionFalse {
		evidence = append(evidence, ConditionEvidence("status.conditions[type=Progressing]",
			"Progressing", string(prog.Status), prog.Reason, prog.Message))
		if prog.Reason == "ProgressDeadlineExceeded" {
			summary += fmt.Sprintf(" The rollout has additionally passed its progressDeadlineSeconds, so "+
				"the controller has stopped waiting and marked it failed. Note that this does not roll "+
				"back: the old ReplicaSet keeps whatever replicas it still has and the new one stays "+
				"stuck, which is why %s can be both 'failed' and still serving traffic.", d.Name)
		}
	}
	if avail := deploymentCondition(d, appsv1.DeploymentReplicaFailure); avail != nil && avail.Status == corev1.ConditionTrue {
		evidence = append(evidence, ConditionEvidence("status.conditions[type=ReplicaFailure]",
			"ReplicaFailure", string(avail.Status), avail.Reason, avail.Message))
		summary += " The ReplicaFailure condition means the ReplicaSet was refused when it tried to " +
			"create a pod, so the pod list will not show the problem — there is no pod."
	}

	if e := snapshot.LatestEvent(quotaRelatedEvents(s, d.Namespace), "FailedCreate"); e != nil {
		evidence = append(evidence, EventEvidence(e))
	}

	return Finding{
		Title:    "Deployment has not converged",
		Severity: severity,
		Subject:  ObjectRef{Kind: "Deployment", Namespace: d.Namespace, Name: d.Name},
		Summary:  summary,
		Evidence: evidence,
		NextSteps: []string{
			fmt.Sprintf("kubectl -n %s rollout status deployment/%s --timeout=10s", d.Namespace, d.Name),
			fmt.Sprintf("kubectl -n %s get pods -l %s", d.Namespace, matchLabelsOf(d.Spec.Selector)),
			describeCmd("deployment", d.Namespace, d.Name),
		},
	}, true
}

func (r rolloutRule) statefulSet(s *snapshot.Snapshot, sts *appsv1.StatefulSet) (Finding, bool) {
	if snapshot.Terminating(&sts.ObjectMeta) {
		return Finding{}, false
	}
	desired := int32(1)
	if sts.Spec.Replicas != nil {
		desired = *sts.Spec.Replicas
	}
	if desired == 0 || sts.Status.ReadyReplicas >= desired {
		return Finding{}, false
	}
	if s.Age(&sts.CreationTimestamp) < StartupGrace {
		return Finding{}, false
	}

	severity := SeverityWarning
	if sts.Status.ReadyReplicas == 0 {
		severity = SeverityCritical
	}

	// The ordering guarantee is what makes a stuck StatefulSet different from a
	// stuck Deployment, and it is the part people forget under pressure.
	summary := fmt.Sprintf(
		"%d of %d replicas are ready. With the default OrderedReady policy a StatefulSet will not "+
			"start pod N+1 until pod N is Running and Ready, so one broken pod stops the whole set "+
			"rather than costing it one replica — check the lowest-numbered unready ordinal first, "+
			"because every pod above it is waiting rather than failing.",
		sts.Status.ReadyReplicas, desired)

	evidence := []Evidence{
		FieldEvidence("spec.replicas", fmt.Sprintf("%d", desired)),
		FieldEvidence("status", fmt.Sprintf("ready=%d current=%d updated=%d",
			sts.Status.ReadyReplicas, sts.Status.CurrentReplicas, sts.Status.UpdatedReplicas)),
		FieldEvidence("spec.podManagementPolicy", string(podManagementPolicy(sts))),
	}

	return Finding{
		Title:    "StatefulSet has not converged",
		Severity: severity,
		Subject:  ObjectRef{Kind: "StatefulSet", Namespace: sts.Namespace, Name: sts.Name},
		Summary:  summary,
		Evidence: evidence,
		NextSteps: []string{
			fmt.Sprintf("kubectl -n %s get pods -l %s", sts.Namespace, matchLabelsOf(sts.Spec.Selector)),
			fmt.Sprintf("kubectl -n %s get pvc -l %s", sts.Namespace, matchLabelsOf(sts.Spec.Selector)),
			describeCmd("statefulset", sts.Namespace, sts.Name),
		},
	}, true
}

// matchLabelsOf renders a controller's selector. The field is a pointer and
// the API server rejects a controller without one, but a snapshot can be
// hand-assembled or truncated, and a nil dereference in a diagnostic tool is
// an especially poor way to end an incident.
func matchLabelsOf(sel *metav1.LabelSelector) string {
	if sel == nil {
		return "<no selector>"
	}
	return formatSelector(sel.MatchLabels)
}

func podManagementPolicy(sts *appsv1.StatefulSet) appsv1.PodManagementPolicyType {
	if sts.Spec.PodManagementPolicy == "" {
		return appsv1.OrderedReadyPodManagement
	}
	return sts.Spec.PodManagementPolicy
}

func deploymentCondition(d *appsv1.Deployment, t appsv1.DeploymentConditionType) *appsv1.DeploymentCondition {
	for i := range d.Status.Conditions {
		if d.Status.Conditions[i].Type == t {
			return &d.Status.Conditions[i]
		}
	}
	return nil
}
