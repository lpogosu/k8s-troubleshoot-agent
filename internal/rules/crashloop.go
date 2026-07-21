package rules

import (
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/lpogosu/k8s-troubleshoot-agent/internal/snapshot"
)

// crashLoopRule explains why a container keeps dying.
//
// The status everyone sees is `CrashLoopBackOff`, which says only that the
// kubelet has started waiting between restarts. The useful signal is one level
// down, in `lastState.terminated`: the exit code, and whether the kernel or an
// operator sent the signal. 137 with `reason: OOMKilled` and 137 without it are
// completely different incidents, and Kubernetes reports both as "restarting".
type crashLoopRule struct{}

func (crashLoopRule) ID() string { return "KTA002" }

func (crashLoopRule) Description() string {
	return "container restarts repeatedly: OOM kill, signal, or non-zero application exit"
}

func (r crashLoopRule) Evaluate(s *snapshot.Snapshot) []Finding {
	var out []Finding
	for i := range s.Pods {
		pod := &s.Pods[i]
		if !diagnosable(pod) {
			continue
		}
		for _, cs := range allContainerStatuses(pod) {
			if !inCrashLoop(cs.status) {
				continue
			}
			// A container that has restarted exactly once inside the grace
			// period is a container that is starting, not one that is
			// looping. Waiting for the second restart costs a few seconds of
			// latency and removes the entire class of false alarms on
			// freshly rolled-out pods.
			if cs.status.RestartCount <= 1 && s.Age(pod.Status.StartTime) < StartupGrace {
				continue
			}
			out = append(out, r.finding(s, pod, cs))
		}
	}
	return out
}

func inCrashLoop(cs *corev1.ContainerStatus) bool {
	if w := cs.State.Waiting; w != nil && w.Reason == "CrashLoopBackOff" {
		return true
	}
	// A container caught mid-cycle is `running` with a terminated lastState
	// and a restart count that keeps climbing; only reporting the waiting
	// state would make the finding blink in and out between collections.
	return cs.RestartCount >= 3 && cs.LastTerminationState.Terminated != nil
}

func (r crashLoopRule) finding(s *snapshot.Snapshot, pod *corev1.Pod, cs containerStatus) Finding {
	name := cs.status.Name
	term := cs.status.LastTerminationState.Terminated
	if term == nil {
		term = cs.status.State.Terminated
	}

	evidence := []Evidence{
		FieldEvidence(cs.statusPath()+".restartCount", fmt.Sprintf("%d", cs.status.RestartCount)),
	}
	if w := cs.status.State.Waiting; w != nil {
		evidence = append(evidence, FieldEvidence(
			cs.statusPath()+".state.waiting",
			strings.TrimSpace(fmt.Sprintf("reason=%s: %s", w.Reason, w.Message)),
		))
	}

	var cause crashCause
	if term == nil {
		// Without a termination record there is nothing to interpret. Say so
		// rather than inventing a cause.
		cause = crashCause{
			title: "container is restarting repeatedly",
			summary: "The container has restarted more than once, but the pod status carries no " +
				"termination record for the previous run, so the exit code is unknown. This happens " +
				"when the kubelet lost the container state across a restart of its own.",
		}
	} else {
		evidence = append(evidence, FieldEvidence(
			cs.statusPath()+".lastState.terminated",
			terminationDetail(term),
		))
		cause = classifyExit(term, pod, name)
	}

	if oom := snapshot.LatestEvent(s.EventsForContainer(pod.Namespace, pod.Name, name), "BackOff", "Unhealthy"); oom != nil {
		evidence = append(evidence, EventEvidence(oom))
	}

	steps := []string{
		fmt.Sprintf("kubectl -n %s logs %s -c %s --previous", pod.Namespace, pod.Name, name),
		describeCmd("pod", pod.Namespace, pod.Name),
	}
	steps = append(steps, cause.steps...)

	summary := cause.summary
	if cs.init {
		summary += " This is an init container: while it keeps failing the application containers " +
			"are never started at all, and the pod stays in Init:Error."
	}

	return Finding{
		Title:     cause.title,
		Severity:  SeverityCritical,
		Subject:   podRef(pod, name),
		Summary:   summary + ownerHint(pod),
		Evidence:  evidence,
		NextSteps: steps,
	}
}

type crashCause struct {
	title   string
	summary string
	steps   []string
}

func terminationDetail(t *corev1.ContainerStateTerminated) string {
	parts := []string{fmt.Sprintf("exitCode=%d", t.ExitCode)}
	if t.Signal != 0 {
		parts = append(parts, fmt.Sprintf("signal=%d", t.Signal))
	}
	if t.Reason != "" {
		parts = append(parts, "reason="+t.Reason)
	}
	if !t.FinishedAt.IsZero() {
		parts = append(parts, "finishedAt="+snapshot.FormatTime(t.FinishedAt))
	}
	if msg := strings.TrimSpace(t.Message); msg != "" {
		parts = append(parts, "message="+msg)
	}
	return strings.Join(parts, " ")
}

// classifyExit turns an exit code into an explanation.
//
// Exit codes above 128 encode a signal: 128+N. The kernel's OOM killer and a
// liveness probe both produce 137 (128+SIGKILL), and the only thing separating
// them in the API is whether the kubelet set `reason: OOMKilled` — so the
// reason is checked before the code, not after.
func classifyExit(t *corev1.ContainerStateTerminated, pod *corev1.Pod, container string) crashCause {
	limit := memoryLimitOf(pod, container)

	switch {
	case t.Reason == "OOMKilled":
		summary := "The kernel killed the container for exceeding its memory limit. This is not the " +
			"application choosing to exit: the process was terminated mid-work with SIGKILL and could " +
			"not clean up."
		if limit != "" {
			summary += fmt.Sprintf(" The limit in force is %s.", limit)
		} else {
			summary += " No memory limit is set on the container, so the kill came from the node " +
				"running out of memory rather than from the container's own cgroup — check the other " +
				"pods on this node too."
		}
		summary += " Either the limit is below what the workload genuinely needs, or the workload is " +
			"leaking; the restart interval tells you which, since a leak takes progressively the same " +
			"time to hit the ceiling while an undersized limit is hit almost immediately."
		return crashCause{
			title:   "container was OOM-killed",
			summary: summary,
			steps: []string{
				fmt.Sprintf("kubectl -n %s get pod %s -o jsonpath='{.spec.containers[?(@.name==\"%s\")].resources}'",
					pod.Namespace, pod.Name, container),
				fmt.Sprintf("kubectl top pod -n %s %s --containers", pod.Namespace, pod.Name),
			},
		}

	case t.ExitCode == 137:
		return crashCause{
			title: "container was killed with SIGKILL",
			summary: "Exit code 137 is 128+9: something sent SIGKILL. The kubelet did not mark it as " +
				"OOMKilled, which rules out the container's own memory limit and leaves a liveness probe " +
				"whose grace period expired, eviction under node pressure, or a runtime shutdown. Check " +
				"the pod's liveness probe timing before anything else — a probe that is stricter than the " +
				"application's real start-up time kills it in a loop that looks exactly like a crash.",
			steps: []string{
				fmt.Sprintf("kubectl -n %s get pod %s -o jsonpath='{.spec.containers[?(@.name==\"%s\")].livenessProbe}'",
					pod.Namespace, pod.Name, container),
				fmt.Sprintf("kubectl -n %s get events --field-selector involvedObject.name=%s", pod.Namespace, pod.Name),
			},
		}

	case t.ExitCode == 143:
		return crashCause{
			title: "container exited on SIGTERM",
			summary: "Exit code 143 is 128+15: the container received SIGTERM and exited without " +
				"handling it. Kubernetes sends SIGTERM to ask for a graceful stop, so this is the " +
				"expected shutdown path — seen in a restart loop it usually means the container is " +
				"being asked to stop shortly after starting, and the reason lies outside the process: " +
				"a rollout replacing it, an eviction, or a liveness probe restarting it. It can also " +
				"mean the application treats SIGTERM as fatal instead of draining.",
		}

	case t.ExitCode == 139:
		return crashCause{
			title: "container crashed with SIGSEGV",
			summary: "Exit code 139 is 128+11: the process segfaulted. This is a fault inside the " +
				"binary or a native dependency, not a Kubernetes problem — the same image will do it " +
				"outside the cluster. A frequent cause in containers specifically is a binary built " +
				"for a different CPU architecture or against a different libc than the base image has.",
		}

	case t.ExitCode == 127:
		return crashCause{
			title: "container command not found",
			summary: "Exit code 127 means the shell could not find the command. The image starts, but " +
				"the entrypoint or the `command`/`args` in the pod spec point at a path that does not " +
				"exist in it — often a binary that lives in the build stage of a multi-stage Dockerfile " +
				"and was never copied into the final one, or a shell that a distroless image does not " +
				"ship.",
			steps: []string{
				fmt.Sprintf("kubectl -n %s get pod %s -o jsonpath='{.spec.containers[?(@.name==\"%s\")]}' | head -c 400",
					pod.Namespace, pod.Name, container),
			},
		}

	case t.ExitCode == 126:
		return crashCause{
			title: "container command is not executable",
			summary: "Exit code 126 means the command was found but could not be run: the executable " +
				"bit is missing, the file is a script with an unusable shebang, or a read-only root " +
				"filesystem or securityContext is blocking execution.",
		}

	case t.ExitCode == 0:
		return crashCause{
			title: "container exits cleanly and is restarted",
			summary: fmt.Sprintf("The container exits with code 0 — it thinks it finished successfully — "+
				"but the pod's restartPolicy is %s, so Kubernetes starts it again, and the loop shows up "+
				"as a crash loop. Either the process is not a long-running server (a script that ends, a "+
				"framework in one-shot mode), or this workload should be a Job rather than a %s.",
				pod.Spec.RestartPolicy, workloadKindOf(pod)),
		}

	default:
		if t.ExitCode > 128 && t.ExitCode < 165 {
			return crashCause{
				title: fmt.Sprintf("container was killed by signal %d", t.ExitCode-128),
				summary: fmt.Sprintf("Exit code %d is 128+%d: the process was terminated by a signal "+
					"rather than exiting on its own. The sender is outside the container, so look at the "+
					"pod's probes and at node-level pressure before the application.",
					t.ExitCode, t.ExitCode-128),
			}
		}
		return crashCause{
			title: fmt.Sprintf("application exits with code %d", t.ExitCode),
			summary: fmt.Sprintf("The container's own process decided to exit with code %d. This is an "+
				"application-level failure, not an infrastructure one: the image runs, the command was "+
				"found, and the process reached its own error path. The previous run's logs carry the "+
				"reason — misconfiguration and an unreachable dependency at start-up are the two common "+
				"ones.", t.ExitCode),
		}
	}
}

func memoryLimitOf(pod *corev1.Pod, container string) string {
	spec := snapshot.ContainerSpec(pod, container)
	if spec == nil {
		return ""
	}
	q, ok := spec.Resources.Limits[corev1.ResourceMemory]
	if !ok {
		return ""
	}
	return q.String()
}

func workloadKindOf(pod *corev1.Pod) string {
	if owner := snapshot.ControllerOf(pod); owner != "" {
		if i := strings.Index(owner, "/"); i > 0 {
			return owner[:i]
		}
	}
	return "long-running workload"
}
