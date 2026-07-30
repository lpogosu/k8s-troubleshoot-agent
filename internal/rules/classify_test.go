package rules

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// The fixtures prove the engine end to end. These tests cover the breadth of
// the classifiers instead: every exit code and every registry error worth
// distinguishing, without a fixture each.

func TestClassifyExit(t *testing.T) {
	podWithLimit := &corev1.Pod{
		Spec: corev1.PodSpec{
			RestartPolicy: corev1.RestartPolicyAlways,
			Containers: []corev1.Container{{
				Name: "app",
				Resources: corev1.ResourceRequirements{
					Limits: corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("256Mi")},
				},
			}},
		},
	}
	podNoLimit := &corev1.Pod{
		Spec: corev1.PodSpec{
			RestartPolicy: corev1.RestartPolicyAlways,
			Containers:    []corev1.Container{{Name: "app"}},
		},
	}

	tests := []struct {
		name            string
		term            corev1.ContainerStateTerminated
		pod             *corev1.Pod
		wantTitle       string
		wantSummaryHas  string
		wantSummaryLack string
	}{
		{
			name:           "oom killed inside its own limit",
			term:           corev1.ContainerStateTerminated{ExitCode: 137, Reason: "OOMKilled"},
			pod:            podWithLimit,
			wantTitle:      "container was OOM-killed",
			wantSummaryHas: "The limit in force is 256Mi",
		},
		{
			name: "oom killed with no limit points at the node, not the container",
			term: corev1.ContainerStateTerminated{ExitCode: 137, Reason: "OOMKilled"},
			pod:  podNoLimit,
			// This distinction matters operationally: with no limit set, the
			// kill came from node-level pressure and the other pods on that
			// node are part of the story.
			wantTitle:      "container was OOM-killed",
			wantSummaryHas: "No memory limit is set",
		},
		{
			name:            "137 without OOMKilled is not an OOM",
			term:            corev1.ContainerStateTerminated{ExitCode: 137, Signal: 9},
			pod:             podWithLimit,
			wantTitle:       "container was killed with SIGKILL",
			wantSummaryHas:  "liveness probe",
			wantSummaryLack: "memory limit is below",
		},
		{
			name:           "143 is a graceful stop request",
			term:           corev1.ContainerStateTerminated{ExitCode: 143},
			pod:            podWithLimit,
			wantTitle:      "container exited on SIGTERM",
			wantSummaryHas: "graceful stop",
		},
		{
			name:           "139 is a segfault in the binary",
			term:           corev1.ContainerStateTerminated{ExitCode: 139},
			pod:            podWithLimit,
			wantTitle:      "container crashed with SIGSEGV",
			wantSummaryHas: "CPU architecture",
		},
		{
			name:           "127 is a missing command",
			term:           corev1.ContainerStateTerminated{ExitCode: 127},
			pod:            podWithLimit,
			wantTitle:      "container command not found",
			wantSummaryHas: "multi-stage Dockerfile",
		},
		{
			name:           "126 is a command that cannot be executed",
			term:           corev1.ContainerStateTerminated{ExitCode: 126},
			pod:            podWithLimit,
			wantTitle:      "container command is not executable",
			wantSummaryHas: "executable bit",
		},
		{
			name:           "exit 0 under restartPolicy Always is a workload-kind mistake",
			term:           corev1.ContainerStateTerminated{ExitCode: 0, Reason: "Completed"},
			pod:            podWithLimit,
			wantTitle:      "container exits cleanly and is restarted",
			wantSummaryHas: "should be a Job",
		},
		{
			name:           "an unmapped signal is still decoded as 128+N",
			term:           corev1.ContainerStateTerminated{ExitCode: 132},
			pod:            podWithLimit,
			wantTitle:      "container was killed by signal 4",
			wantSummaryHas: "terminated by a signal",
		},
		{
			name:           "an ordinary application exit code is not dressed up",
			term:           corev1.ContainerStateTerminated{ExitCode: 2},
			pod:            podWithLimit,
			wantTitle:      "application exits with code 2",
			wantSummaryHas: "not an infrastructure one",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyExit(&tt.term, tt.pod, "app")
			if got.title != tt.wantTitle {
				t.Errorf("title = %q, want %q", got.title, tt.wantTitle)
			}
			if !strings.Contains(got.summary, tt.wantSummaryHas) {
				t.Errorf("summary does not mention %q\n  got: %s", tt.wantSummaryHas, got.summary)
			}
			if tt.wantSummaryLack != "" && strings.Contains(got.summary, tt.wantSummaryLack) {
				t.Errorf("summary must not mention %q\n  got: %s", tt.wantSummaryLack, got.summary)
			}
		})
	}
}

func TestClassifyPullFailure(t *testing.T) {
	withSecret := &corev1.Pod{Spec: corev1.PodSpec{
		ImagePullSecrets: []corev1.LocalObjectReference{{Name: "regcred"}},
	}}
	withoutSecret := &corev1.Pod{}

	tests := []struct {
		name           string
		message        string
		image          string
		pod            *corev1.Pod
		wantTitle      string
		wantSummaryHas string
	}{
		{
			name:      "ghcr reports an unknown tag",
			message:   `failed to resolve reference "ghcr.io/example/api:v9": ghcr.io/example/api:v9: not found`,
			image:     "ghcr.io/example/api:v9",
			pod:       withoutSecret,
			wantTitle: "image reference does not exist in the registry",
		},
		{
			name:      "docker distribution reports an unknown manifest",
			message:   "manifest unknown: manifest tagged by \"nope\" is not found",
			image:     "registry.example/app:nope",
			pod:       withoutSecret,
			wantTitle: "image reference does not exist in the registry",
		},
		{
			name:           "401 with no pull secret at all",
			message:        "pull access denied, repository does not exist or may require authorization",
			image:          "registry.example/private/app:1.0",
			pod:            withoutSecret,
			wantTitle:      "registry credentials rejected",
			wantSummaryHas: "no imagePullSecrets at all",
		},
		{
			name:           "401 even though a pull secret is attached",
			message:        "Error response from daemon: unauthorized: authentication required",
			image:          "registry.example/private/app:1.0",
			pod:            withSecret,
			wantTitle:      "registry credentials rejected",
			wantSummaryHas: "regcred",
		},
		{
			name:      "docker hub throttling",
			message:   "toomanyrequests: You have reached your pull rate limit.",
			image:     "nginx:1.27",
			pod:       withoutSecret,
			wantTitle: "registry is rate-limiting this node",
		},
		{
			name:      "429 without the word rate limit",
			message:   "unexpected status code 429 Too Many Requests",
			image:     "nginx:1.27",
			pod:       withoutSecret,
			wantTitle: "registry is rate-limiting this node",
		},
		{
			name:      "dns failure reaching the registry",
			message:   `dial tcp: lookup registry.internal on 10.96.0.10:53: no such host`,
			image:     "registry.internal/app:1.0",
			pod:       withoutSecret,
			wantTitle: "registry is unreachable from the node",
		},
		{
			name:      "a private CA the node does not trust",
			message:   "x509: certificate signed by unknown authority",
			image:     "registry.internal/app:1.0",
			pod:       withoutSecret,
			wantTitle: "registry is unreachable from the node",
		},
		{
			name:      "an unsubstituted template variable",
			message:   `couldn't parse image name "${IMAGE_TAG}": invalid reference format`,
			image:     "${IMAGE_TAG}",
			pod:       withoutSecret,
			wantTitle: "image reference is malformed",
		},
		{
			name:           "an unrecognised message is admitted as such",
			message:        "something the registry has never said before",
			image:          "example/app:1.0",
			pod:            withoutSecret,
			wantTitle:      "image pull failed",
			wantSummaryHas: "does not match any known pattern",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyPullFailure(tt.message, tt.image, tt.pod)
			if got.title != tt.wantTitle {
				t.Errorf("title = %q, want %q", got.title, tt.wantTitle)
			}
			if tt.wantSummaryHas != "" && !strings.Contains(got.summary, tt.wantSummaryHas) {
				t.Errorf("summary does not mention %q\n  got: %s", tt.wantSummaryHas, got.summary)
			}
		})
	}
}

// TestClassifySchedulingFindsEveryBlocker matters because the scheduler packs
// several independent reasons into one sentence. Reporting only the first
// would tell the reader to add a node when a taint is also in the way.
func TestClassifySchedulingFindsEveryBlocker(t *testing.T) {
	tests := []struct {
		name    string
		message string
		want    []schedulingReason
	}{
		{
			name:    "insufficient cpu only",
			message: "0/3 nodes are available: 3 Insufficient cpu.",
			want:    []schedulingReason{reasonInsufficientCPU},
		},
		{
			name: "cpu on some nodes and a taint on the rest",
			message: "0/4 nodes are available: 1 node(s) had untolerated taint " +
				"{node-role.kubernetes.io/control-plane: }, 3 Insufficient cpu.",
			want: []schedulingReason{reasonInsufficientCPU, reasonTaint},
		},
		{
			name:    "node selector mismatch",
			message: "0/2 nodes are available: 2 node(s) didn't match Pod's node affinity/selector.",
			want:    []schedulingReason{reasonNodeSelector},
		},
		{
			name:    "unbound claim",
			message: "0/2 nodes are available: pod has unbound immediate PersistentVolumeClaims.",
			want:    []schedulingReason{reasonUnboundVolume},
		},
		{
			name:    "volume pinned to a zone the pod cannot reach",
			message: "0/6 nodes are available: 6 node(s) had volume node affinity conflict.",
			want:    []schedulingReason{reasonVolumeAffinity},
		},
		{
			name:    "anti-affinity with more replicas than nodes",
			message: "0/3 nodes are available: 3 node(s) didn't satisfy existing pods anti-affinity rules.",
			want:    []schedulingReason{reasonAffinityRules},
		},
		{
			name:    "memory and pods exhausted together",
			message: "0/5 nodes are available: 2 Insufficient memory, 3 Insufficient pods.",
			want:    []schedulingReason{reasonInsufficientMemory, reasonOtherResource},
		},
		{
			name:    "a message the tool does not recognise yields nothing",
			message: "0/3 nodes are available: 3 some future scheduler plugin said no.",
			want:    nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyScheduling(tt.message)
			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("reason %d = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestClassifyMountFailure(t *testing.T) {
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "edge"}}
	tests := []struct {
		name      string
		message   string
		wantTitle string
	}{
		{
			name:      "missing secret",
			message:   `MountVolume.SetUp failed for volume "creds" : secret "db" not found`,
			wantTitle: "a Secret the pod mounts does not exist",
		},
		{
			name:      "missing configmap",
			message:   `MountVolume.SetUp failed for volume "cfg" : configmap "app" not found`,
			wantTitle: "a ConfigMap the pod mounts does not exist",
		},
		{
			name:      "attach timeout",
			message:   `Unable to attach or mount volumes: unmounted volumes=[data]: timed out waiting for the condition`,
			wantTitle: "volume attach or mount timed out",
		},
		{
			name:      "the disk is still held by the previous node",
			message:   "Multi-Attach error for volume \"pvc-abc\" Volume is already used by pod(s) db-0",
			wantTitle: "volume is still attached to another node",
		},
		{
			name:      "cni failure",
			message:   `Failed to create pod sandbox: plugin type="bridge" failed (add): failed to allocate for range 0`,
			wantTitle: "the pod sandbox could not be created",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			title, summary := classifyMountFailure(tt.message, pod)
			if title != tt.wantTitle {
				t.Errorf("title = %q, want %q", title, tt.wantTitle)
			}
			if strings.TrimSpace(summary) == "" {
				t.Error("summary is empty")
			}
		})
	}
}

// TestQuantityRatio guards the arithmetic behind the quota rule. Quantity has
// no division, and memory values in bytes are large enough that a naive
// conversion is a real overflow risk rather than a theoretical one.
func TestQuantityRatio(t *testing.T) {
	tests := []struct {
		name      string
		used      string
		hard      string
		want      float64
		tolerance float64
	}{
		{name: "pod counts", used: "10", hard: "10", want: 1.0, tolerance: 0.001},
		{name: "cpu in millicores", used: "9500m", hard: "10", want: 0.95, tolerance: 0.001},
		{name: "memory in gibibytes", used: "18Gi", hard: "20Gi", want: 0.9, tolerance: 0.001},
		{name: "terabyte-scale memory does not overflow", used: "1Ti", hard: "4Ti", want: 0.25, tolerance: 0.001},
		{name: "empty quota is not a division by zero", used: "5", hard: "0", want: 0, tolerance: 0.001},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := quantityRatio(resource.MustParse(tt.used), resource.MustParse(tt.hard))
			if diff := got - tt.want; diff > tt.tolerance || diff < -tt.tolerance {
				t.Errorf("ratio = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSplitByPressure(t *testing.T) {
	quota := &corev1.ResourceQuota{
		Status: corev1.ResourceQuotaStatus{
			Hard: corev1.ResourceList{
				"pods":            resource.MustParse("10"),
				"requests.cpu":    resource.MustParse("10"),
				"requests.memory": resource.MustParse("20Gi"),
				"services":        resource.MustParse("5"),
			},
			Used: corev1.ResourceList{
				"pods":            resource.MustParse("10"),    // exhausted
				"requests.cpu":    resource.MustParse("9500m"), // 95%, tight
				"requests.memory": resource.MustParse("4Gi"),   // 20%, fine
				"services":        resource.MustParse("2"),     // fine
			},
		},
	}

	exhausted, tight := splitByPressure(quota)
	if len(exhausted) != 1 || exhausted[0].name != "pods" {
		t.Errorf("exhausted = %v, want [pods]", exhausted)
	}
	if len(tight) != 1 || tight[0].name != "requests.cpu" {
		t.Errorf("tight = %v, want [requests.cpu]", tight)
	}
}

// TestSeverityOrdering pins the comparison that drives both the output order
// and the --min-severity filter.
func TestSeverityOrdering(t *testing.T) {
	if !SeverityCritical.AtLeast(SeverityWarning) {
		t.Error("critical must satisfy a warning threshold")
	}
	if SeverityWarning.AtLeast(SeverityCritical) {
		t.Error("warning must not satisfy a critical threshold")
	}
	if !SeverityInfo.AtLeast(SeverityInfo) {
		t.Error("a severity must satisfy its own threshold")
	}

	if _, err := ParseSeverity("WARNING"); err != nil {
		t.Errorf("ParseSeverity is case-insensitive: %v", err)
	}
	if _, err := ParseSeverity("urgent"); err == nil {
		t.Error("ParseSeverity must reject an unknown level rather than defaulting")
	}
}

func TestObjectRefString(t *testing.T) {
	tests := []struct {
		ref  ObjectRef
		want string
	}{
		{ObjectRef{Kind: "Pod", Namespace: "shop", Name: "web-1"}, "shop/pod/web-1"},
		{ObjectRef{Kind: "Pod", Namespace: "shop", Name: "web-1", Container: "app"}, "shop/pod/web-1 [app]"},
		{ObjectRef{Kind: "Node", Name: "worker-2"}, "node/worker-2"},
	}
	for _, tt := range tests {
		if got := tt.ref.String(); got != tt.want {
			t.Errorf("String() = %q, want %q", got, tt.want)
		}
	}
}

func TestRepoOfStripsTagAndDigest(t *testing.T) {
	tests := []struct{ ref, want string }{
		{"nginx:1.27", "nginx"},
		{"ghcr.io/example/api:v2", "ghcr.io/example/api"},
		{"ghcr.io/example/api@sha256:abc123", "ghcr.io/example/api"},
		// A port in the registry host is the case a naive LastIndex(":") gets
		// wrong, turning localhost:5000/app into localhost.
		{"localhost:5000/app", "localhost:5000/app"},
		{"localhost:5000/app:1.2", "localhost:5000/app"},
	}
	for _, tt := range tests {
		if got := repoOf(tt.ref); got != tt.want {
			t.Errorf("repoOf(%q) = %q, want %q", tt.ref, got, tt.want)
		}
	}
}
