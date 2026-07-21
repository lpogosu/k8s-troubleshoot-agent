package rules

import (
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/lpogosu/k8s-troubleshoot-agent/internal/snapshot"
)

// readinessRule explains a pod that runs but never becomes Ready.
//
// This is the quietest of the common failures: the pod shows `1/1 Running`
// alongside `0/1` ready, nothing crashes, no event screams, and the workload is
// simply absent from every Service. The signal is the Ready condition being
// false while the container is genuinely running.
type readinessRule struct{}

func (readinessRule) ID() string { return "KTA006" }

func (readinessRule) Description() string {
	return "container runs but fails its readiness probe, so it is kept out of Service endpoints"
}

func (r readinessRule) Evaluate(s *snapshot.Snapshot) []Finding {
	var out []Finding
	for i := range s.Pods {
		pod := &s.Pods[i]
		if !diagnosable(pod) || pod.Status.Phase != corev1.PodRunning {
			continue
		}
		ready := snapshot.PodCondition(pod, corev1.PodReady)
		if ready == nil || ready.Status == corev1.ConditionTrue {
			continue
		}
		// Readiness probes have an initialDelaySeconds and a failureThreshold
		// for a reason; a pod inside its own start-up window is not failing,
		// it is starting. Firing here would flag every pod during every
		// rollout.
		if s.Age(pod.Status.StartTime) < StartupGrace {
			continue
		}
		for _, cs := range allContainerStatuses(pod) {
			if cs.init || cs.status.Ready || cs.status.State.Running == nil {
				continue
			}
			// A container that is also crash-looping is KTA002's story; two
			// findings about the same container would just compete.
			if inCrashLoop(cs.status) {
				continue
			}
			out = append(out, r.finding(s, pod, cs, ready))
		}
	}
	return out
}

func (r readinessRule) finding(
	s *snapshot.Snapshot,
	pod *corev1.Pod,
	cs containerStatus,
	ready *corev1.PodCondition,
) Finding {
	name := cs.status.Name
	spec := snapshot.ContainerSpec(pod, name)

	evidence := []Evidence{
		ConditionEvidence("status.conditions[type=Ready]", "Ready", string(ready.Status), ready.Reason, ready.Message),
		FieldEvidence(cs.statusPath()+".ready", "false"),
		FieldEvidence(cs.statusPath()+".state", "running since "+runningSince(cs.status)),
	}

	unhealthy := snapshot.LatestEvent(s.EventsForContainer(pod.Namespace, pod.Name, name), "Unhealthy", "ProbeWarning")
	if unhealthy != nil {
		evidence = append(evidence, EventEvidence(unhealthy))
	}

	probe := ""
	if spec != nil && spec.ReadinessProbe != nil {
		probe = describeProbe(spec.ReadinessProbe)
		evidence = append(evidence, FieldEvidence(cs.specPath(pod, "readinessProbe"), probe))
	}

	summary := "The container process is up — it has not exited and is not restarting — but its " +
		"readiness probe keeps failing, so Kubernetes deliberately keeps the pod out of every Service " +
		"that selects it. From the outside the workload looks deployed and receives no traffic at all."

	switch {
	case unhealthy != nil && snapshot.MessageMatchesAny(unhealthy.Message, "connection refused"):
		summary += " The probe was refused at the TCP level, which means nothing is listening on that " +
			"port inside the container: either the application binds a different port than the probe " +
			"targets, or it binds 127.0.0.1 instead of 0.0.0.0 and is unreachable from the kubelet."
	case unhealthy != nil && snapshot.MessageMatchesAny(unhealthy.Message, "timeout", "context deadline exceeded", "i/o timeout"):
		summary += " The probe timed out rather than being refused, so the port is open and the " +
			"handler is too slow to answer. Check what the readiness endpoint does — one that reaches " +
			"into a database turns every dependency hiccup into a full outage of this workload."
	case unhealthy != nil && snapshot.MessageMatchesAny(unhealthy.Message, "http probe failed", "statuscode"):
		summary += " The endpoint answered with a status code the probe treats as failure, so the " +
			"application is running and reporting itself as not ready. Its own logs, not the cluster, " +
			"hold the reason."
	case spec != nil && spec.ReadinessProbe == nil:
		summary += " No readiness probe is defined on this container, so the Ready condition is coming " +
			"from elsewhere — a readiness gate, or another container in the same pod."
	}

	if probe != "" {
		summary += fmt.Sprintf(" The probe in force is %s.", probe)
	}

	return Finding{
		Title:    "container is running but never becomes ready",
		Severity: SeverityCritical,
		Subject:  podRef(pod, name),
		Summary:  summary + ownerHint(pod),
		Evidence: evidence,
		NextSteps: []string{
			fmt.Sprintf("kubectl -n %s logs %s -c %s --tail=50", pod.Namespace, pod.Name, name),
			describeCmd("pod", pod.Namespace, pod.Name),
			fmt.Sprintf("kubectl -n %s port-forward %s %s   # then probe the path by hand",
				pod.Namespace, pod.Name, probePortHint(spec)),
		},
	}
}

func runningSince(cs *corev1.ContainerStatus) string {
	if cs.State.Running == nil {
		return "an unknown time"
	}
	return snapshot.FormatTime(cs.State.Running.StartedAt)
}

func describeProbe(p *corev1.Probe) string {
	var target string
	switch {
	case p.HTTPGet != nil:
		scheme := strings.ToLower(string(p.HTTPGet.Scheme))
		if scheme == "" {
			scheme = "http"
		}
		target = fmt.Sprintf("%s GET %s on port %s", scheme, p.HTTPGet.Path, p.HTTPGet.Port.String())
	case p.TCPSocket != nil:
		target = "TCP connect to port " + p.TCPSocket.Port.String()
	case p.Exec != nil:
		target = "exec " + strings.Join(p.Exec.Command, " ")
	case p.GRPC != nil:
		target = fmt.Sprintf("gRPC health check on port %d", p.GRPC.Port)
	default:
		target = "an unrecognised probe handler"
	}
	return fmt.Sprintf("%s, initialDelay=%ds period=%ds timeout=%ds failureThreshold=%d",
		target, p.InitialDelaySeconds, p.PeriodSeconds, p.TimeoutSeconds, p.FailureThreshold)
}

func probePortHint(spec *corev1.Container) string {
	if spec != nil && spec.ReadinessProbe != nil && spec.ReadinessProbe.HTTPGet != nil {
		port := spec.ReadinessProbe.HTTPGet.Port.String()
		return port + ":" + port
	}
	if spec != nil && len(spec.Ports) > 0 {
		p := fmt.Sprintf("%d", spec.Ports[0].ContainerPort)
		return p + ":" + p
	}
	return "<local>:<container>"
}
