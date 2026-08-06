// Package snapshot defines the serialisable view of a cluster that the rule
// engine consumes.
//
// Rules never talk to an API server: they only ever see a Snapshot. That is
// what lets the same rule run against a live cluster, against a file captured
// an hour ago, and against a fixture in a unit test — with identical results.
package snapshot

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Format is the version tag written into every snapshot. It is checked on
// load: an old file silently misread by new rules produces confident wrong
// answers, which is worse than refusing to run.
const Format = "kubediag.snapshot/v1"

// Snapshot is a point-in-time, read-only copy of the cluster objects the rules
// need. Everything a rule reasons about must be in here — a rule that reaches
// for anything else cannot be tested offline.
type Snapshot struct {
	Format     string      `json:"format"`
	CapturedAt metav1.Time `json:"capturedAt"`
	Source     Source      `json:"source"`

	Pods                   []corev1.Pod                   `json:"pods"`
	Events                 []corev1.Event                 `json:"events"`
	Deployments            []appsv1.Deployment            `json:"deployments"`
	StatefulSets           []appsv1.StatefulSet           `json:"statefulSets"`
	Nodes                  []corev1.Node                  `json:"nodes"`
	PersistentVolumeClaims []corev1.PersistentVolumeClaim `json:"persistentVolumeClaims"`
	Services               []corev1.Service               `json:"services"`
	EndpointSlices         []discoveryv1.EndpointSlice    `json:"endpointSlices"`
	ResourceQuotas         []corev1.ResourceQuota         `json:"resourceQuotas"`
}

// Source records where a snapshot came from, so a finding can be traced back
// to a cluster and a moment rather than to an anonymous file.
type Source struct {
	Context           string `json:"context,omitempty"`
	Server            string `json:"server,omitempty"`
	KubernetesVersion string `json:"kubernetesVersion,omitempty"`
	// Namespace is empty when the whole cluster was collected. Rules use it to
	// avoid claiming "no pod matches this Service" when the pods simply were
	// not in scope.
	Namespace string `json:"namespace,omitempty"`
}

// ClusterWide reports whether the snapshot covers every namespace. Rules that
// argue from absence must not fire on a namespace-scoped snapshot.
func (s *Snapshot) ClusterWide() bool { return s.Source.Namespace == "" }

// Age returns how long before capture the given timestamp occurred.
//
// This is the only clock the rules get. A rule that called time.Now would give
// a different answer every day it was run against the same fixture, and the
// whole snapshot design rests on that not happening. A zero or future
// timestamp yields zero, so a caller comparing against a grace period treats
// "unknown" as "just now" and stays quiet.
func (s *Snapshot) Age(t *metav1.Time) time.Duration {
	if t == nil || t.IsZero() || s.CapturedAt.IsZero() {
		return 0
	}
	d := s.CapturedAt.Sub(t.Time)
	if d < 0 {
		return 0
	}
	return d
}

// FormatTime renders a timestamp for display, always in UTC.
//
// This is not cosmetic. metav1.Time.UnmarshalJSON converts to the local zone,
// so without normalising here the same snapshot would print different times in
// Yerevan and in London — and this output is pasted into tickets, diffed
// between runs, and compared against what the API server stored, which is UTC.
func FormatTime(t metav1.Time) string {
	if t.IsZero() {
		return "unknown"
	}
	return t.UTC().Format("2006-01-02T15:04:05Z")
}

// Write encodes the snapshot as indented JSON. Indented because these files are
// read by humans and diffed in bug reports; the size penalty is irrelevant next
// to that.
func (s *Snapshot) Write(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(s); err != nil {
		return fmt.Errorf("encode snapshot: %w", err)
	}
	return nil
}

// Save writes the snapshot to path, creating or truncating it.
func (s *Snapshot) Save(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	if err := s.Write(f); err != nil {
		_ = f.Close() // the write error above is the one worth reporting
		return err
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close %s: %w", path, err)
	}
	return nil
}

// Read decodes a snapshot and rejects anything written by an incompatible
// version of the tool.
func Read(r io.Reader) (*Snapshot, error) {
	var s Snapshot
	dec := json.NewDecoder(r)
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("decode snapshot: %w", err)
	}
	if s.Format != Format {
		return nil, fmt.Errorf("unsupported snapshot format %q, expected %q", s.Format, Format)
	}
	return &s, nil
}

// Load reads a snapshot from a file path, or from stdin when path is "-".
func Load(path string) (*Snapshot, error) {
	if path == "-" {
		return Read(os.Stdin)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }() // read-only handle, nothing to flush
	return Read(f)
}
