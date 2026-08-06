package snapshot

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestRoundTripPreservesTypedObjects(t *testing.T) {
	captured := metav1.Date(2026, 7, 16, 9, 41, 22, 0, time.UTC)
	original := &Snapshot{
		Format:     Format,
		CapturedAt: captured,
		Source:     Source{Context: "kind-diag", Namespace: "shop"},
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Name: "web-1", Namespace: "shop"},
			Spec: corev1.PodSpec{
				NodeName:   "worker-1",
				Containers: []corev1.Container{{Name: "app", Image: "nginx:1.27"}},
			},
			Status: corev1.PodStatus{
				Phase: corev1.PodRunning,
				ContainerStatuses: []corev1.ContainerStatus{{
					Name:         "app",
					RestartCount: 3,
					LastTerminationState: corev1.ContainerState{
						Terminated: &corev1.ContainerStateTerminated{ExitCode: 137, Reason: "OOMKilled"},
					},
				}},
			},
		}},
	}

	var buf bytes.Buffer
	if err := original.Write(&buf); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := Read(&buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	if !got.CapturedAt.Equal(&captured) {
		t.Errorf("capturedAt = %v, want %v", got.CapturedAt, captured)
	}
	if len(got.Pods) != 1 {
		t.Fatalf("got %d pods, want 1", len(got.Pods))
	}
	term := got.Pods[0].Status.ContainerStatuses[0].LastTerminationState.Terminated
	if term == nil || term.ExitCode != 137 || term.Reason != "OOMKilled" {
		t.Errorf("termination state did not survive the round trip: %+v", term)
	}
	if got.Source.Namespace != "shop" {
		t.Errorf("source namespace = %q, want shop", got.Source.Namespace)
	}
}

func TestSaveAndLoadRoundTripThroughAFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snapshot.json")
	original := &Snapshot{
		Format:     Format,
		CapturedAt: metav1.Date(2026, 7, 16, 9, 41, 22, 0, time.UTC),
		Source:     Source{Context: "kind-diag", KubernetesVersion: "v1.32.3"},
		Nodes:      []corev1.Node{{ObjectMeta: metav1.ObjectMeta{Name: "worker-1"}}},
	}

	if err := original.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(got.Nodes) != 1 || got.Nodes[0].Name != "worker-1" {
		t.Errorf("nodes did not survive the file round trip: %+v", got.Nodes)
	}
	if got.Source.KubernetesVersion != "v1.32.3" {
		t.Errorf("source = %+v", got.Source)
	}

	// The file is written indented on purpose: these get read and diffed by
	// people, and a single-line snapshot cannot be reviewed.
	raw, err := os.ReadFile(path) //nolint:gosec // a path this test just created
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !strings.Contains(string(raw), "\n  \"format\"") {
		t.Error("the snapshot file should be indented JSON")
	}
}

func TestLoadReportsAMissingFileClearly(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "absent.json"))
	if err == nil {
		t.Fatal("loading a missing file must fail")
	}
	if !strings.Contains(err.Error(), "absent.json") {
		t.Errorf("the error should name the path, got: %v", err)
	}
}

// TestReadRejectsForeignFormat matters more than it looks: a snapshot silently
// misread by a newer rule set produces confident wrong diagnoses, which is
// worse than an error.
func TestReadRejectsForeignFormat(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"a future format version", `{"format":"kubediag.snapshot/v2","pods":[]}`},
		{"no format field at all", `{"pods":[]}`},
		{"a kubectl dump rather than a snapshot", `{"apiVersion":"v1","kind":"List","items":[]}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Read(strings.NewReader(tt.body)); err == nil {
				t.Fatal("expected an error, got none")
			} else if !strings.Contains(err.Error(), "format") {
				t.Errorf("error should name the format problem, got: %v", err)
			}
		})
	}
}

func TestAgeUsesCaptureTimeNotWallClock(t *testing.T) {
	// The capture time is deliberately far in the past. A rule that reached
	// for time.Now would compute an age of years here and behave differently
	// every day the test runs.
	captured := metav1.Date(2026, 7, 16, 9, 41, 22, 0, time.UTC)
	s := &Snapshot{CapturedAt: captured}

	fiveMinutesEarlier := metav1.NewTime(captured.Add(-5 * time.Minute))
	if got := s.Age(&fiveMinutesEarlier); got != 5*time.Minute {
		t.Errorf("age = %v, want 5m", got)
	}

	// A timestamp after the capture is clock skew between the node and the
	// control plane, not a negative age.
	later := metav1.NewTime(captured.Add(time.Minute))
	if got := s.Age(&later); got != 0 {
		t.Errorf("age of a future timestamp = %v, want 0", got)
	}
	if got := s.Age(nil); got != 0 {
		t.Errorf("age of a nil timestamp = %v, want 0", got)
	}
	if got := (&Snapshot{}).Age(&fiveMinutesEarlier); got != 0 {
		t.Errorf("age against an unset capture time = %v, want 0", got)
	}
}

// TestFormatTimeIsAlwaysUTC pins a choice that is easy to regress and hard to
// notice. metav1.Time.UnmarshalJSON converts to the local zone, so a snapshot
// decoded in Yerevan carries +04:00 timestamps and one decoded in London
// carries +00:00 — for the identical file. Rendering in UTC is what makes two
// people diagnosing the same snapshot see the same output.
func TestFormatTimeIsAlwaysUTC(t *testing.T) {
	moscow := time.FixedZone("MSK", 3*60*60)
	local := metav1.NewTime(time.Date(2026, 7, 16, 12, 41, 22, 0, moscow))

	if got := FormatTime(local); got != "2026-07-16T09:41:22Z" {
		t.Errorf("FormatTime = %q, want the same instant in UTC", got)
	}
	if got := FormatTime(metav1.Time{}); got != "unknown" {
		t.Errorf("an unset timestamp must not render as a year-1 date, got %q", got)
	}
}

func TestEventTimeFallsBackAcrossApiVersions(t *testing.T) {
	base := time.Date(2026, 7, 16, 9, 0, 0, 0, time.UTC)

	tests := []struct {
		name  string
		event corev1.Event
		want  time.Time
	}{
		{
			name:  "legacy core/v1 event",
			event: corev1.Event{LastTimestamp: metav1.NewTime(base)},
			want:  base,
		},
		{
			name: "events/v1 style, only eventTime set",
			event: corev1.Event{
				EventTime: metav1.NewMicroTime(base.Add(time.Minute)),
			},
			want: base.Add(time.Minute),
		},
		{
			name: "a deduplicated series wins over lastTimestamp",
			event: corev1.Event{
				LastTimestamp: metav1.NewTime(base),
				Series: &corev1.EventSeries{
					Count:            9,
					LastObservedTime: metav1.NewMicroTime(base.Add(2 * time.Minute)),
				},
			},
			want: base.Add(2 * time.Minute),
		},
		{
			name:  "only firstTimestamp survived",
			event: corev1.Event{FirstTimestamp: metav1.NewTime(base.Add(-time.Hour))},
			want:  base.Add(-time.Hour),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := EventTime(&tt.event); !got.Time.Equal(tt.want) {
				t.Errorf("EventTime = %v, want %v", got.Time, tt.want)
			}
		})
	}
}

func TestEventCountNormalisesBothRepresentations(t *testing.T) {
	tests := []struct {
		name  string
		event corev1.Event
		want  int32
	}{
		{"legacy count", corev1.Event{Count: 12}, 12},
		{"series count", corev1.Event{Series: &corev1.EventSeries{Count: 34}}, 34},
		{"neither set means it happened once", corev1.Event{}, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := EventCount(&tt.event); got != tt.want {
				t.Errorf("EventCount = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestLatestEventPicksTheNewestMatchingReason(t *testing.T) {
	base := time.Date(2026, 7, 16, 9, 0, 0, 0, time.UTC)
	events := []corev1.Event{
		{ObjectMeta: metav1.ObjectMeta{Name: "old"}, Reason: "Failed", LastTimestamp: metav1.NewTime(base)},
		{ObjectMeta: metav1.ObjectMeta{Name: "new"}, Reason: "Failed", LastTimestamp: metav1.NewTime(base.Add(time.Hour))},
		{ObjectMeta: metav1.ObjectMeta{Name: "other"}, Reason: "BackOff", LastTimestamp: metav1.NewTime(base.Add(2 * time.Hour))},
	}

	if got := LatestEvent(events, "Failed"); got == nil || got.Name != "new" {
		t.Errorf("LatestEvent picked %v, want the newer Failed event", got)
	}
	if got := LatestEvent(events, "Unhealthy"); got != nil {
		t.Errorf("LatestEvent matched %v when no event has that reason", got.Name)
	}
	// Reason matching must be exact: "Failed" must not swallow "FailedMount",
	// which is a different problem with a different fix.
	mount := []corev1.Event{{ObjectMeta: metav1.ObjectMeta{Name: "m"}, Reason: "FailedMount"}}
	if got := LatestEvent(mount, "Failed"); got != nil {
		t.Error(`reason "Failed" must not match "FailedMount"`)
	}
}

func TestEventsForMatchesOnKindNotJustName(t *testing.T) {
	s := &Snapshot{Events: []corev1.Event{
		{
			ObjectMeta:     metav1.ObjectMeta{Name: "a"},
			InvolvedObject: corev1.ObjectReference{Kind: "Pod", Namespace: "shop", Name: "web"},
		},
		{
			ObjectMeta:     metav1.ObjectMeta{Name: "b"},
			InvolvedObject: corev1.ObjectReference{Kind: "Service", Namespace: "shop", Name: "web"},
		},
	}}

	got := s.EventsFor("Pod", "shop", "web")
	if len(got) != 1 || got[0].Name != "a" {
		t.Errorf("EventsFor returned %d events, want only the Pod one", len(got))
	}
}

func TestEventsForContainerKeepsPodScopedEvents(t *testing.T) {
	s := &Snapshot{Events: []corev1.Event{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "container-scoped"},
			InvolvedObject: corev1.ObjectReference{
				Kind: "Pod", Namespace: "shop", Name: "web", FieldPath: "spec.containers{app}",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "other-container"},
			InvolvedObject: corev1.ObjectReference{
				Kind: "Pod", Namespace: "shop", Name: "web", FieldPath: "spec.containers{sidecar}",
			},
		},
		{
			// The scheduler writes no field path; the event still belongs to
			// this container's pod and must not be filtered away.
			ObjectMeta:     metav1.ObjectMeta{Name: "pod-scoped"},
			InvolvedObject: corev1.ObjectReference{Kind: "Pod", Namespace: "shop", Name: "web"},
		},
	}}

	got := s.EventsForContainer("shop", "web", "app")
	names := make([]string, 0, len(got))
	for _, e := range got {
		names = append(names, e.Name)
	}
	if len(got) != 2 {
		t.Fatalf("got %v, want the container-scoped and the pod-scoped events", names)
	}
	for _, n := range names {
		if n == "other-container" {
			t.Error("an event for a different container leaked in")
		}
	}
}

func TestPodsMatchingTreatsAnEmptySelectorAsMatchingNothing(t *testing.T) {
	s := &Snapshot{Pods: []corev1.Pod{
		{ObjectMeta: metav1.ObjectMeta{Name: "a", Namespace: "shop", Labels: map[string]string{"app": "web"}}},
		{ObjectMeta: metav1.ObjectMeta{Name: "b", Namespace: "shop", Labels: map[string]string{"app": "api"}}},
		{ObjectMeta: metav1.ObjectMeta{Name: "c", Namespace: "other", Labels: map[string]string{"app": "web"}}},
	}}

	if got := s.PodsMatching("shop", map[string]string{"app": "web"}); len(got) != 1 || got[0].Name != "a" {
		t.Errorf("selector app=web in shop matched %d pods, want just a", len(got))
	}
	// An empty selector on a Service means "endpoints are managed elsewhere",
	// not "every pod in the namespace". Getting this backwards would make the
	// Service rule route findings at every unrelated pod.
	if got := s.PodsMatching("shop", nil); len(got) != 0 {
		t.Errorf("an empty selector matched %d pods, want 0", len(got))
	}
}

func TestControllerOfNamesTheOwningController(t *testing.T) {
	controller := true
	notController := false
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{OwnerReferences: []metav1.OwnerReference{
		{Kind: "ConfigMap", Name: "unrelated", Controller: &notController},
		{Kind: "ReplicaSet", Name: "web-6d9f", Controller: &controller},
	}}}
	if got := ControllerOf(pod); got != "ReplicaSet/web-6d9f" {
		t.Errorf("ControllerOf = %q, want ReplicaSet/web-6d9f", got)
	}
	if got := ControllerOf(&corev1.Pod{}); got != "" {
		t.Errorf("a bare pod has no controller, got %q", got)
	}
}

func TestClusterWide(t *testing.T) {
	if !(&Snapshot{}).ClusterWide() {
		t.Error("an empty namespace scope means the whole cluster")
	}
	if (&Snapshot{Source: Source{Namespace: "shop"}}).ClusterWide() {
		t.Error("a namespaced snapshot is not cluster-wide")
	}
}
