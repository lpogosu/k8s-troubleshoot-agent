package rules

import (
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/lpogosu/k8s-troubleshoot-agent/internal/snapshot"
)

// imagePullRule explains why the kubelet cannot fetch a container image.
//
// `ImagePullBackOff` on its own is close to useless: it is the same status for
// a typo in a tag, a missing pull secret and Docker Hub throttling, and the
// three have nothing in common operationally. The waiting reason tells you the
// kubelet gave up; the registry's own words, which land in the Failed event,
// tell you why.
type imagePullRule struct{}

func (imagePullRule) ID() string { return "KTA001" }

func (imagePullRule) Description() string {
	return "image cannot be pulled: wrong reference, missing credentials, throttling or unreachable registry"
}

// pullCause is the classification of a registry error message.
type pullCause struct {
	title   string
	summary string
	// steps are appended after the generic describe command.
	steps []string
}

func (r imagePullRule) Evaluate(s *snapshot.Snapshot) []Finding {
	var out []Finding
	for i := range s.Pods {
		pod := &s.Pods[i]
		if !diagnosable(pod) {
			continue
		}
		for _, cs := range allContainerStatuses(pod) {
			waiting := cs.status.State.Waiting
			if waiting == nil || !isImagePullReason(waiting.Reason) {
				continue
			}
			out = append(out, r.finding(s, pod, cs, waiting))
		}
	}
	return out
}

func isImagePullReason(reason string) bool {
	switch reason {
	case "ImagePullBackOff", "ErrImagePull", "ImageInspectError", "RegistryUnavailable", "InvalidImageName":
		return true
	default:
		return false
	}
}

func (r imagePullRule) finding(
	s *snapshot.Snapshot,
	pod *corev1.Pod,
	cs containerStatus,
	waiting *corev1.ContainerStateWaiting,
) Finding {
	name := cs.status.Name
	image := cs.status.Image
	if spec := snapshot.ContainerSpec(pod, name); spec != nil && spec.Image != "" {
		// The spec image is the reference the user wrote; status.Image can be
		// the resolved one, or empty when the pull never got that far.
		image = spec.Image
	}

	events := s.EventsForContainer(pod.Namespace, pod.Name, name)
	failed := snapshot.LatestEvent(events, "Failed", "FailedPull")

	registryMsg := waiting.Message
	if failed != nil && len(failed.Message) > len(registryMsg) {
		// The Failed event carries the registry's verbatim reply; the waiting
		// message is often just "Back-off pulling image".
		registryMsg = failed.Message
	}

	cause := classifyPullFailure(registryMsg, image, pod)

	evidence := []Evidence{
		FieldEvidence(
			cs.statusPath()+".state.waiting",
			fmt.Sprintf("reason=%s: %s", waiting.Reason, strings.TrimSpace(waiting.Message)),
		),
		FieldEvidence(cs.specPath(pod, "image"), image),
	}
	if failed != nil {
		evidence = append(evidence, EventEvidence(failed))
	}
	if len(pod.Spec.ImagePullSecrets) > 0 {
		evidence = append(evidence, FieldEvidence("spec.imagePullSecrets", pullSecretNames(pod)))
	} else {
		evidence = append(evidence, FieldEvidence("spec.imagePullSecrets", "not set"))
	}

	steps := append([]string{describeCmd("pod", pod.Namespace, pod.Name)}, cause.steps...)

	return Finding{
		Title:     cause.title,
		Severity:  SeverityCritical,
		Subject:   podRef(pod, name),
		Summary:   cause.summary + ownerHint(pod),
		Evidence:  evidence,
		NextSteps: steps,
	}
}

func pullSecretNames(pod *corev1.Pod) string {
	names := make([]string, 0, len(pod.Spec.ImagePullSecrets))
	for _, s := range pod.Spec.ImagePullSecrets {
		names = append(names, s.Name)
	}
	return strings.Join(names, ", ")
}

// classifyPullFailure maps the registry's error text onto a cause.
//
// The order matters. "unauthorized" appears inside the message a registry
// returns for a private repository that exists *and* for one that does not —
// registries deliberately do not distinguish the two, so a 401 is reported as
// credentials first, with the alternative named in the summary rather than
// guessed at.
func classifyPullFailure(msg, image string, pod *corev1.Pod) pullCause {
	ref := imageRef(image)
	switch {
	case snapshot.MessageMatchesAny(msg, "toomanyrequests", "rate limit", "429"):
		return pullCause{
			title: "registry is rate-limiting this node",
			summary: "The registry accepted the request but refused to serve the image because " +
				"the pull quota for this source address is spent. Nothing about the workload is " +
				"wrong: the same manifest will start once the window resets, or immediately from " +
				"an authenticated or mirrored registry.",
			steps: []string{
				"kubectl get pods -A -o jsonpath='{range .items[*]}{.spec.containers[*].image}{\"\\n\"}{end}' | sort | uniq -c | sort -rn | head",
			},
		}

	case snapshot.MessageMatchesAny(msg, "pull access denied", "authentication required", "unauthorized", "401", "denied: requested access"):
		summary := fmt.Sprintf(
			"The registry rejected the credentials for %s. Registries answer 401 both for a private "+
				"image and for one that does not exist, so this is either a missing or wrong pull "+
				"secret, or a reference into a repository this account cannot see.", ref)
		if len(pod.Spec.ImagePullSecrets) == 0 {
			summary += " The pod carries no imagePullSecrets at all, and the service account does not " +
				"add one, so the kubelet pulled anonymously."
		} else {
			summary += fmt.Sprintf(" The pod does reference %s — check that the secret exists in "+
				"namespace %s and that its registry host matches the image.",
				pullSecretNames(pod), pod.Namespace)
		}
		return pullCause{
			title:   "registry credentials rejected",
			summary: summary,
			steps: []string{
				fmt.Sprintf("kubectl -n %s get secret %s -o jsonpath='{.data.\\.dockerconfigjson}' | base64 -d", pod.Namespace, firstPullSecret(pod)),
				fmt.Sprintf("kubectl -n %s get serviceaccount %s -o jsonpath='{.imagePullSecrets}'", pod.Namespace, serviceAccountName(pod)),
			},
		}

	case snapshot.MessageMatchesAny(msg, "manifest unknown", "manifest for", "not found", "404", "manifest tagged"):
		return pullCause{
			title: "image reference does not exist in the registry",
			summary: fmt.Sprintf(
				"The registry answered, was reachable, and has no such image: %s. In practice this is "+
					"a tag that was never pushed or was deleted — a typo in the tag, a build that failed "+
					"before push, or a digest pinned to an image that has since been garbage-collected.", ref),
			steps: []string{
				fmt.Sprintf("crane ls %s   # or: docker manifest inspect %s", repoOf(ref), ref),
			},
		}

	case snapshot.MessageMatchesAny(msg, "no such host", "i/o timeout", "connection refused", "dial tcp", "tls handshake", "certificate signed by unknown authority"):
		return pullCause{
			title: "registry is unreachable from the node",
			summary: fmt.Sprintf(
				"The pull failed at the network layer, before any authentication or lookup: the node "+
					"could not open a working connection to the registry serving %s. Look at node egress, "+
					"DNS inside the cluster, a proxy that needs configuring in the container runtime, or a "+
					"private registry whose CA the node does not trust.", ref),
			steps: []string{
				fmt.Sprintf("kubectl get node %s -o wide", pod.Spec.NodeName),
			},
		}

	case snapshot.MessageMatchesAny(msg, "invalid reference format", "couldn't parse image", "repository name must be"):
		return pullCause{
			title: "image reference is malformed",
			summary: fmt.Sprintf(
				"The kubelet never contacted a registry: %q is not a valid image reference. Usually an "+
					"unsubstituted template variable or a stray character from a generated manifest.", image),
			steps: nil,
		}

	default:
		return pullCause{
			title: "image pull failed",
			summary: fmt.Sprintf(
				"The kubelet is backing off from pulling %s and the registry error does not match any "+
					"known pattern, so the message above is the primary evidence rather than this "+
					"summary.", ref),
			steps: nil,
		}
	}
}

// imageRef falls back to a placeholder so summaries never read "image  is
// missing" when the status did not carry a reference.
func imageRef(image string) string {
	if image == "" {
		return "the container image"
	}
	return image
}

// repoOf strips the tag or digest, keeping any registry host and port.
func repoOf(ref string) string {
	if at := strings.Index(ref, "@"); at >= 0 {
		ref = ref[:at]
	}
	slash := strings.LastIndex(ref, "/")
	if colon := strings.LastIndex(ref, ":"); colon > slash {
		ref = ref[:colon]
	}
	return ref
}

func firstPullSecret(pod *corev1.Pod) string {
	if len(pod.Spec.ImagePullSecrets) == 0 {
		return "<name>"
	}
	return pod.Spec.ImagePullSecrets[0].Name
}

func serviceAccountName(pod *corev1.Pod) string {
	if pod.Spec.ServiceAccountName != "" {
		return pod.Spec.ServiceAccountName
	}
	return "default"
}
