package rules

import (
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/lpogosu/k8s-troubleshoot-agent/internal/snapshot"
)

// Severity orders findings by how much they demand attention now.
type Severity string

const (
	// SeverityCritical marks a workload that is not serving and will not
	// recover on its own.
	SeverityCritical Severity = "critical"
	// SeverityWarning marks degradation: serving, but with less capacity or
	// less headroom than intended.
	SeverityWarning Severity = "warning"
	// SeverityInfo marks context that explains another finding but is not a
	// fault by itself.
	SeverityInfo Severity = "info"
)

var severityRank = map[Severity]int{
	SeverityCritical: 0,
	SeverityWarning:  1,
	SeverityInfo:     2,
}

// Rank returns the sort weight of a severity; unknown values sort last.
func (s Severity) Rank() int {
	if r, ok := severityRank[s]; ok {
		return r
	}
	return len(severityRank)
}

// AtLeast reports whether s is at least as severe as the given threshold.
func (s Severity) AtLeast(threshold Severity) bool { return s.Rank() <= threshold.Rank() }

// ParseSeverity converts a CLI value into a Severity.
func ParseSeverity(v string) (Severity, error) {
	switch Severity(strings.ToLower(v)) {
	case SeverityCritical:
		return SeverityCritical, nil
	case SeverityWarning:
		return SeverityWarning, nil
	case SeverityInfo:
		return SeverityInfo, nil
	default:
		return "", fmt.Errorf("unknown severity %q (want critical, warning or info)", v)
	}
}

// ObjectRef identifies the object a finding is about.
type ObjectRef struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
	// Container is set when the fault is specific to one container of a pod.
	Container string `json:"container,omitempty"`
}

// String renders the reference the way kubectl would print it.
func (o ObjectRef) String() string {
	s := strings.ToLower(o.Kind) + "/" + o.Name
	if o.Namespace != "" {
		s = o.Namespace + "/" + s
	}
	if o.Container != "" {
		s += " [" + o.Container + "]"
	}
	return s
}

// EvidenceKind says where a piece of evidence was read from, so a reader can
// tell a fact reported by the cluster from an inference made by this tool.
type EvidenceKind string

const (
	// EvidenceEvent is a Kubernetes Event.
	EvidenceEvent EvidenceKind = "event"
	// EvidenceCondition is a status condition on an object.
	EvidenceCondition EvidenceKind = "condition"
	// EvidenceField is a value read directly from an object's spec or status.
	EvidenceField EvidenceKind = "field"
)

// Evidence is one verifiable observation from the snapshot. Every finding
// carries at least one: a diagnosis the reader cannot check against the
// cluster is an opinion, and this tool does not have opinions.
type Evidence struct {
	Kind EvidenceKind `json:"kind"`
	// Source is the exact origin — a JSON path into the object, a condition
	// type, or an event reason — so the reader can go and look at it.
	Source string `json:"source"`
	// Detail is the observed value, quoted rather than paraphrased.
	Detail string `json:"detail"`
	// ObservedAt is when the cluster recorded it, when that is known.
	ObservedAt *metav1.Time `json:"observedAt,omitempty"`
	// Count is the event repetition count; zero for non-events.
	Count int32 `json:"count,omitempty"`
}

// FieldEvidence builds evidence read straight off an object.
func FieldEvidence(path, detail string) Evidence {
	return Evidence{Kind: EvidenceField, Source: path, Detail: detail}
}

// ConditionEvidence renders a status condition, including its reason and
// message — the reason alone is rarely enough to act on.
func ConditionEvidence(path, condType, status, reason, message string) Evidence {
	detail := fmt.Sprintf("%s=%s", condType, status)
	if reason != "" {
		detail += " reason=" + reason
	}
	if message != "" {
		detail += ": " + message
	}
	return Evidence{Kind: EvidenceCondition, Source: path, Detail: detail}
}

// EventEvidence renders a Kubernetes event with its reason, repetition count
// and timestamp.
func EventEvidence(e *corev1.Event) Evidence {
	at := snapshot.EventTime(e)
	ev := Evidence{
		Kind:   EvidenceEvent,
		Source: fmt.Sprintf("Event/%s reason=%s from=%s", e.Name, e.Reason, eventSource(e)),
		Detail: strings.TrimSpace(e.Message),
		Count:  snapshot.EventCount(e),
	}
	if !at.IsZero() {
		ev.ObservedAt = &at
	}
	return ev
}

func eventSource(e *corev1.Event) string {
	if e.Source.Component != "" {
		return e.Source.Component
	}
	if e.ReportingController != "" {
		return e.ReportingController
	}
	return "unknown"
}

// Finding is one diagnosis: what is wrong, what it rests on, and what to run
// next.
type Finding struct {
	RuleID   string    `json:"ruleId"`
	Title    string    `json:"title"`
	Severity Severity  `json:"severity"`
	Subject  ObjectRef `json:"subject"`
	// Summary explains the fault in prose, without jargon that the reader
	// would have to look up.
	Summary string `json:"summary"`
	// Evidence is never empty; the engine drops findings that fail this.
	Evidence []Evidence `json:"evidence"`
	// NextSteps are commands, ready to paste, that confirm or fix the
	// diagnosis. They are read-only wherever a read-only command exists.
	NextSteps []string `json:"nextSteps,omitempty"`
}

// SortFindings orders findings the way an operator wants to read them: worst
// first, then grouped by namespace and object. The order is total and
// deterministic, because the text output is diffed in bug reports.
func SortFindings(findings []Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.Severity.Rank() != b.Severity.Rank() {
			return a.Severity.Rank() < b.Severity.Rank()
		}
		if a.Subject.Namespace != b.Subject.Namespace {
			return a.Subject.Namespace < b.Subject.Namespace
		}
		if a.Subject.Name != b.Subject.Name {
			return a.Subject.Name < b.Subject.Name
		}
		if a.Subject.Container != b.Subject.Container {
			return a.Subject.Container < b.Subject.Container
		}
		return a.RuleID < b.RuleID
	})
}
