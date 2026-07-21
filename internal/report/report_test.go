package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/lpogosu/k8s-troubleshoot-agent/internal/rules"
	"github.com/lpogosu/k8s-troubleshoot-agent/internal/snapshot"
)

func sampleSnapshot() *snapshot.Snapshot {
	return &snapshot.Snapshot{
		Format:     snapshot.Format,
		CapturedAt: metav1.Date(2026, 7, 16, 9, 41, 22, 0, time.UTC),
		Source:     snapshot.Source{Context: "kind-diag"},
	}
}

func sampleFindings() []rules.Finding {
	observed := metav1.Date(2026, 7, 16, 9, 40, 0, 0, time.UTC)
	return []rules.Finding{
		{
			RuleID:   "KTA002",
			Title:    "container was OOM-killed",
			Severity: rules.SeverityCritical,
			Subject:  rules.ObjectRef{Kind: "Pod", Namespace: "payments", Name: "ledger-1", Container: "app"},
			Summary:  "The kernel killed the container for exceeding its memory limit.",
			Evidence: []rules.Evidence{
				rules.FieldEvidence("status.containerStatuses[0].lastState.terminated", "exitCode=137 reason=OOMKilled"),
				{Kind: rules.EvidenceEvent, Source: "Event/backoff reason=BackOff from=kubelet",
					Detail: "Back-off restarting failed container", Count: 23, ObservedAt: &observed},
			},
			NextSteps: []string{"kubectl -n payments logs ledger-1 -c app --previous"},
		},
		{
			RuleID:   "KTA009",
			Title:    "node is cordoned",
			Severity: rules.SeverityInfo,
			Subject:  rules.ObjectRef{Kind: "Node", Name: "worker-2"},
			Summary:  "The node is marked unschedulable.",
			Evidence: []rules.Evidence{rules.FieldEvidence("spec.unschedulable", "true")},
		},
	}
}

func TestWriteTextRendersEverythingAFindingClaims(t *testing.T) {
	rep := Build(sampleSnapshot(), rules.NewDefaultEngine(), sampleFindings())

	var buf bytes.Buffer
	if err := WriteText(&buf, rep); err != nil {
		t.Fatalf("WriteText: %v", err)
	}
	out := buf.String()

	for _, want := range []string{
		"CRITICAL",
		"container was OOM-killed",
		"payments/pod/ledger-1 [app]",
		"KTA002",
		"exitCode=137 reason=OOMKilled",
		"[event]",
		"(x23)",
		"kubectl -n payments logs ledger-1 -c app --previous",
		"node/worker-2",
		"1 critical, 1 info",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("text output is missing %q\n---\n%s", want, out)
		}
	}
}

// TestWriteTextIsPlainAscii guards a deliberate choice: this output is pasted
// into tickets and chat far more often than it is admired in a terminal, and
// escape codes survive neither.
func TestWriteTextIsPlainAscii(t *testing.T) {
	rep := Build(sampleSnapshot(), rules.NewDefaultEngine(), sampleFindings())
	var buf bytes.Buffer
	if err := WriteText(&buf, rep); err != nil {
		t.Fatalf("WriteText: %v", err)
	}
	if strings.Contains(buf.String(), "\x1b[") {
		t.Error("the text report must not contain ANSI escape sequences")
	}
}

// TestWriteTextOnACleanRunSaysWhatCleanMeans is a wording test on purpose. "No
// findings" read as "the cluster is healthy" is the single most damaging way
// this tool could be misunderstood.
func TestWriteTextOnACleanRunSaysWhatCleanMeans(t *testing.T) {
	rep := Build(sampleSnapshot(), rules.NewDefaultEngine(), nil)
	var buf bytes.Buffer
	if err := WriteText(&buf, rep); err != nil {
		t.Fatalf("WriteText: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, "No findings") {
		t.Errorf("a clean run must say so plainly:\n%s", out)
	}
	if !strings.Contains(out, "not a statement that the") {
		t.Errorf("a clean run must not be presented as a health guarantee:\n%s", out)
	}
	if !strings.Contains(out, "scanned:") {
		t.Errorf("a clean run must report what was scanned, or it is indistinguishable from no data:\n%s", out)
	}
}

func TestWriteTextWrapsProseButNotCommands(t *testing.T) {
	long := strings.Repeat("the summary explains the fault in ordinary words. ", 12)
	command := "kubectl -n payments get pod ledger-1 -o jsonpath='{.spec.containers[?(@.name==\"app\")].resources}'"

	rep := Build(sampleSnapshot(), rules.NewDefaultEngine(), []rules.Finding{{
		RuleID:    "KTA002",
		Title:     "t",
		Severity:  rules.SeverityCritical,
		Subject:   rules.ObjectRef{Kind: "Pod", Namespace: "payments", Name: "ledger-1"},
		Summary:   long,
		Evidence:  []rules.Evidence{rules.FieldEvidence("f", "v")},
		NextSteps: []string{command},
	}})

	var buf bytes.Buffer
	if err := WriteText(&buf, rep); err != nil {
		t.Fatalf("WriteText: %v", err)
	}

	for _, line := range strings.Split(buf.String(), "\n") {
		if strings.Contains(line, "kubectl") {
			// A wrapped command cannot be copied, which defeats the point of
			// printing it.
			if !strings.Contains(line, command) {
				t.Errorf("the next-step command was broken across lines: %q", line)
			}
			continue
		}
		if len([]rune(line)) > wrapWidth+2 {
			t.Errorf("prose line is %d runes, wrap width is %d: %q", len([]rune(line)), wrapWidth, line)
		}
	}
}

func TestWrapDoesNotSplitLongTokens(t *testing.T) {
	// An image digest is longer than the wrap width and must stay copyable.
	digest := strings.Repeat("a", 120)
	got := wrap("image "+digest+" failed", 40)
	if !strings.Contains(got, digest) {
		t.Errorf("a token longer than the width was split:\n%s", got)
	}
}

func TestWriteJSONIsMachineReadableAndKeepsEvidence(t *testing.T) {
	rep := Build(sampleSnapshot(), rules.NewDefaultEngine(), sampleFindings())

	var buf bytes.Buffer
	if err := WriteJSON(&buf, rep); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}

	var decoded Report
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("the JSON output must round-trip: %v", err)
	}

	if decoded.Tool != "kubediag" {
		t.Errorf("tool = %q", decoded.Tool)
	}
	if len(decoded.Findings) != 2 {
		t.Fatalf("got %d findings, want 2", len(decoded.Findings))
	}
	if decoded.Findings[0].RuleID != "KTA002" {
		t.Errorf("a consumer suppresses rules by id; the id must survive, got %q", decoded.Findings[0].RuleID)
	}
	if len(decoded.Findings[0].Evidence) != 2 {
		t.Error("evidence must survive into JSON: it is how a consumer re-checks a claim")
	}
	if decoded.Summary["critical"] != 1 || decoded.Summary["info"] != 1 {
		t.Errorf("summary counts = %v", decoded.Summary)
	}
	if len(decoded.RulesRun) != len(rules.All()) {
		t.Errorf("rulesRun lists %d rules, want %d", len(decoded.RulesRun), len(rules.All()))
	}
}

// TestWriteJSONDoesNotEscapeHtml protects the commands and registry messages,
// which are full of characters Go's encoder escapes by default.
func TestWriteJSONDoesNotEscapeHtml(t *testing.T) {
	rep := Build(sampleSnapshot(), rules.NewDefaultEngine(), []rules.Finding{{
		RuleID:    "KTA002",
		Title:     "t",
		Severity:  rules.SeverityCritical,
		Subject:   rules.ObjectRef{Kind: "Pod", Name: "p"},
		Summary:   "s",
		Evidence:  []rules.Evidence{rules.FieldEvidence("f", "v")},
		NextSteps: []string{"kubectl logs p > out.txt && grep -c 'x' out.txt"},
	}})

	var buf bytes.Buffer
	if err := WriteJSON(&buf, rep); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	// Raw strings on purpose: the assertion is about the six literal characters
	// the encoder writes when escaping is on, not about the character itself.
	if strings.Contains(buf.String(), `\u003e`) || strings.Contains(buf.String(), `\u0026`) {
		t.Errorf("a command was HTML-escaped and is no longer copyable:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "out.txt && grep") {
		t.Errorf("the command did not survive verbatim:\n%s", buf.String())
	}
}

func TestWorstReportsTheHighestSeverity(t *testing.T) {
	rep := Build(sampleSnapshot(), rules.NewDefaultEngine(), sampleFindings())
	worst, ok := rep.Worst()
	if !ok || worst != rules.SeverityCritical {
		t.Errorf("Worst() = %q, %v; want critical, true", worst, ok)
	}

	clean := Build(sampleSnapshot(), rules.NewDefaultEngine(), nil)
	if _, ok := clean.Worst(); ok {
		t.Error("a report with no findings has no worst severity")
	}
}

// TestBuildRecordsWhatWasScanned covers the difference between "the rules ran
// and found nothing" and "the rules had nothing to look at", which look
// identical without these counts.
func TestBuildRecordsWhatWasScanned(t *testing.T) {
	snap := sampleSnapshot()
	snap.Pods = []corev1.Pod{{}, {}, {}}
	snap.Nodes = []corev1.Node{{}}
	snap.Services = []corev1.Service{{}, {}}

	rep := Build(snap, rules.NewDefaultEngine(), nil)

	if rep.Scanned.Pods != 3 || rep.Scanned.Nodes != 1 || rep.Scanned.Services != 2 {
		t.Errorf("scanned counts = %+v", rep.Scanned)
	}
	if got := rep.Scanned.describe(); !strings.Contains(got, "3 pods") || !strings.Contains(got, "1 nodes") {
		t.Errorf("describe() = %q", got)
	}
}
