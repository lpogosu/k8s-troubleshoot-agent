package rules

import (
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/lpogosu/k8s-troubleshoot-agent/internal/snapshot"
)

// volumeMountRule explains a pod stuck in ContainerCreating.
//
// This state has no condition and no exit code — the pod simply never
// progresses, and `kubectl get pods` shows `ContainerCreating` forever. The
// reason lives only in the kubelet's FailedMount event, which is exactly the
// place people forget to look because the pod's own status is empty.
type volumeMountRule struct{}

func (volumeMountRule) ID() string { return "KTA004" }

func (volumeMountRule) Description() string {
	return "pod stuck creating: a Secret, ConfigMap or volume it mounts cannot be attached"
}

func (r volumeMountRule) Evaluate(s *snapshot.Snapshot) []Finding {
	var out []Finding
	for i := range s.Pods {
		pod := &s.Pods[i]
		if !diagnosable(pod) || pod.Status.Phase != corev1.PodPending {
			continue
		}
		// The pod has a node, so scheduling succeeded: whatever is wrong now is
		// the kubelet's, not the scheduler's. Without this check the finding
		// would double up with KTA003 on every Pending pod.
		if pod.Spec.NodeName == "" {
			continue
		}
		events := s.EventsFor("Pod", pod.Namespace, pod.Name)
		failed := snapshot.LatestEvent(events, "FailedMount", "FailedAttachVolume", "FailedCreatePodSandBox")
		if failed == nil {
			continue
		}
		// A mount that has been retried once is normal — attaching a network
		// disk takes seconds. One that is still failing after the grace period
		// is not going to fix itself.
		if snapshot.EventCount(failed) < 2 && s.Age(pod.Status.StartTime) < StartupGrace {
			continue
		}
		out = append(out, r.finding(pod, failed))
	}
	return out
}

func (r volumeMountRule) finding(pod *corev1.Pod, failed *corev1.Event) Finding {
	title, summary := classifyMountFailure(failed.Message, pod)

	evidence := []Evidence{
		EventEvidence(failed),
		FieldEvidence("status.phase", string(pod.Status.Phase)),
		FieldEvidence("spec.nodeName", pod.Spec.NodeName),
	}
	if vols := volumeSummary(pod); vols != "" {
		evidence = append(evidence, FieldEvidence("spec.volumes", vols))
	}

	return Finding{
		Title:    title,
		Severity: SeverityCritical,
		Subject:  podRef(pod, ""),
		Summary:  summary + ownerHint(pod),
		NextSteps: []string{
			describeCmd("pod", pod.Namespace, pod.Name),
			fmt.Sprintf("kubectl -n %s get secret,configmap,pvc", pod.Namespace),
		},
		Evidence: evidence,
	}
}

func classifyMountFailure(msg string, pod *corev1.Pod) (title, summary string) {
	switch {
	case snapshot.MessageMatchesAny(msg, "secret"):
		return "a Secret the pod mounts does not exist",
			fmt.Sprintf("The pod was scheduled, but the kubelet cannot build it: a Secret named in "+
				"spec.volumes is absent from namespace %s. Deployment order is the usual cause — the "+
				"workload was applied before the Secret, or the Secret lives in another namespace and "+
				"cannot be referenced across the boundary. The pod will start on its own the moment the "+
				"Secret appears; no restart is needed.", pod.Namespace)

	case snapshot.MessageMatchesAny(msg, "configmap"):
		return "a ConfigMap the pod mounts does not exist",
			fmt.Sprintf("A ConfigMap referenced by spec.volumes is missing from namespace %s. The "+
				"kubelet retries indefinitely, so the pod recovers by itself once the ConfigMap is "+
				"created — but until then it never reaches Running and never appears in any Service.",
				pod.Namespace)

	case snapshot.MessageMatchesAny(msg, "timed out waiting for the condition", "unable to attach or mount volumes"):
		return "volume attach or mount timed out",
			"The kubelet asked for the volume and never got it. For a network-attached disk this is " +
				"usually the CSI driver: it can be down on this node, or the volume is still attached to " +
				"the node that previously ran the pod, which blocks ReadWriteOnce volumes for as long as " +
				"the old attachment survives."

	case snapshot.MessageMatchesAny(msg, "multi-attach error"):
		return "volume is still attached to another node",
			"A ReadWriteOnce volume can only be mounted on one node at a time, and the previous pod's " +
				"node still holds it. This is what a rolling update of a StatefulSet-like workload with a " +
				"single RWO disk looks like when the old pod does not terminate: the new pod waits for an " +
				"attachment that is not being released."

	case snapshot.MessageMatchesAny(msg, "failed to create pod sandbox", "network", "cni"):
		return "the pod sandbox could not be created",
			"The kubelet failed before any container was started, while setting up the pod's network " +
				"namespace. This points at the CNI plugin on this node rather than at the workload — the " +
				"same manifest will start on a healthy node."

	default:
		return "pod cannot be created on its node",
			"The pod was scheduled but the kubelet cannot bring it up. The event message above is the " +
				"primary evidence; this tool does not recognise the specific failure."
	}
}

func volumeSummary(pod *corev1.Pod) string {
	var parts []string
	for _, v := range pod.Spec.Volumes {
		switch {
		case v.Secret != nil:
			parts = append(parts, "secret:"+v.Secret.SecretName)
		case v.ConfigMap != nil:
			parts = append(parts, "configMap:"+v.ConfigMap.Name)
		case v.PersistentVolumeClaim != nil:
			parts = append(parts, "pvc:"+v.PersistentVolumeClaim.ClaimName)
		case v.Projected != nil:
			parts = append(parts, "projected:"+v.Name)
		}
	}
	return strings.Join(parts, " ")
}

// unboundClaimRule explains a PersistentVolumeClaim that never binds.
//
// It is reported on the claim rather than on the pod on purpose: one unbound
// claim can hold up several pods, and fixing it is a storage-side action.
type unboundClaimRule struct{}

func (unboundClaimRule) ID() string { return "KTA005" }

func (unboundClaimRule) Description() string {
	return "PersistentVolumeClaim stays Pending: no provisioner, no matching volume, or an unknown class"
}

func (r unboundClaimRule) Evaluate(s *snapshot.Snapshot) []Finding {
	var out []Finding
	for i := range s.PersistentVolumeClaims {
		claim := &s.PersistentVolumeClaims[i]
		if snapshot.Terminating(&claim.ObjectMeta) || claim.Status.Phase != corev1.ClaimPending {
			continue
		}
		if s.Age(&claim.CreationTimestamp) < StartupGrace {
			continue
		}
		out = append(out, r.finding(s, claim))
	}
	return out
}

func (r unboundClaimRule) finding(s *snapshot.Snapshot, claim *corev1.PersistentVolumeClaim) Finding {
	events := s.EventsFor("PersistentVolumeClaim", claim.Namespace, claim.Name)
	latest := snapshot.LatestEvent(events, "ProvisioningFailed", "FailedBinding", "WaitForFirstConsumer", "WaitForPodScheduled")

	class := "not set (the cluster default StorageClass applies)"
	if claim.Spec.StorageClassName != nil {
		class = *claim.Spec.StorageClassName
		if class == "" {
			class = `"" (explicitly no dynamic provisioning — a matching PersistentVolume must exist already)`
		}
	}

	evidence := []Evidence{
		FieldEvidence("status.phase", string(claim.Status.Phase)),
		FieldEvidence("spec.storageClassName", class),
		FieldEvidence("spec.resources.requests.storage", requestedStorage(claim)),
	}
	if latest != nil {
		evidence = append(evidence, EventEvidence(latest))
	}

	title := "PersistentVolumeClaim is not bound"
	summary := fmt.Sprintf("The claim has been Pending since it was created, so nothing has provided "+
		"storage for it. Every pod that mounts %s stays Pending as a consequence.", claim.Name)

	if latest != nil {
		switch {
		case latest.Reason == "WaitForFirstConsumer":
			title = "PersistentVolumeClaim is waiting for a pod (WaitForFirstConsumer)"
			summary = "The StorageClass binds with WaitForFirstConsumer, so the claim stays Pending " +
				"until a pod that uses it is scheduled — this is correct behaviour, not a fault. It " +
				"becomes a real deadlock only if that pod is itself unschedulable for another reason, " +
				"since then neither side can move first."
		case snapshot.MessageMatchesAny(latest.Message, "storageclass", "not found"):
			title = "the claim references a StorageClass that does not exist"
			summary = fmt.Sprintf("No StorageClass named %s is registered in the cluster, so no "+
				"provisioner ever picks the claim up. This is the usual outcome of moving a manifest "+
				"between clusters: storage class names are cluster-local and rarely match.", class)
		case snapshot.MessageMatchesAny(latest.Message, "no persistent volumes available", "no volume plugin matched"):
			title = "no PersistentVolume matches the claim"
			summary = "Static provisioning is in use and no existing PersistentVolume satisfies the " +
				"claim's size, access mode and selector at once. Access mode is the field that most " +
				"often mismatches silently."
		}
	}

	severity := SeverityCritical
	if latest != nil && latest.Reason == "WaitForFirstConsumer" {
		severity = SeverityInfo
	}

	return Finding{
		Title:    title,
		Severity: severity,
		Subject:  ObjectRef{Kind: "PersistentVolumeClaim", Namespace: claim.Namespace, Name: claim.Name},
		Summary:  summary,
		Evidence: evidence,
		NextSteps: []string{
			describeCmd("pvc", claim.Namespace, claim.Name),
			"kubectl get storageclass",
		},
	}
}

func requestedStorage(claim *corev1.PersistentVolumeClaim) string {
	q, ok := claim.Spec.Resources.Requests[corev1.ResourceStorage]
	if !ok {
		return "not set"
	}
	return q.String()
}
