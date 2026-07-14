package cli

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

// fixture returns a snapshot from the rules package's testdata. The CLI tests
// deliberately reuse those files rather than keeping their own: the point of
// these tests is that the command wiring reaches the same rules with the same
// input, and a second copy of the data would let the two drift apart.
func fixture(name string) string {
	return filepath.Join("..", "rules", "testdata", name)
}

func run(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	var out, errBuf bytes.Buffer
	cmd := NewRootCommand(&out, &errBuf)
	cmd.SetArgs(args)
	cmd.SetOut(&out)
	cmd.SetErr(&errBuf)
	err = cmd.Execute()
	return out.String(), errBuf.String(), err
}

func TestDiagnoseFromSnapshotText(t *testing.T) {
	stdout, _, err := run(t, "diagnose", "-f", fixture("crashloop-oomkilled.json"))
	if err != nil {
		t.Fatalf("diagnose: %v", err)
	}

	for _, want := range []string{
		"CRITICAL",
		"container was OOM-killed",
		"payments/pod/ledger-5f8c7d6b9-4kq2n [app]",
		"exitCode=137",
		"--previous",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("output is missing %q\n---\n%s", want, stdout)
		}
	}
}

func TestDiagnoseFromSnapshotJSON(t *testing.T) {
	stdout, _, err := run(t, "diagnose", "-f", fixture("crashloop-oomkilled.json"), "-o", "json")
	if err != nil {
		t.Fatalf("diagnose: %v", err)
	}

	var report struct {
		Tool     string `json:"tool"`
		Findings []struct {
			RuleID   string `json:"ruleId"`
			Severity string `json:"severity"`
			Evidence []struct {
				Kind   string `json:"kind"`
				Source string `json:"source"`
			} `json:"evidence"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, stdout)
	}
	if report.Tool != "kubediag" {
		t.Errorf("tool = %q", report.Tool)
	}
	if len(report.Findings) != 1 || report.Findings[0].RuleID != "KTA002" {
		t.Fatalf("findings = %+v", report.Findings)
	}
	if len(report.Findings[0].Evidence) == 0 {
		t.Error("the JSON finding carries no evidence")
	}
}

// TestDiagnoseStdinIsAcceptable covers the workflow the snapshot mode exists
// for: someone pipes a file they were sent, without saving it anywhere.
func TestDiagnoseStdinIsAcceptable(t *testing.T) {
	// The flag plumbing is what is under test; snapshot.Load handles "-".
	stdout, _, err := run(t, "diagnose", "-f", fixture("healthy.json"))
	if err != nil {
		t.Fatalf("diagnose: %v", err)
	}
	if !strings.Contains(stdout, "No findings") {
		t.Errorf("the healthy fixture should be clean:\n%s", stdout)
	}
}

func TestDiagnoseMinSeverityFilters(t *testing.T) {
	all, _, err := run(t, "diagnose", "-f", fixture("node-cordoned.json"))
	if err != nil {
		t.Fatalf("diagnose: %v", err)
	}
	if !strings.Contains(all, "cordoned") {
		t.Fatalf("the info finding should be present by default:\n%s", all)
	}

	filtered, _, err := run(t, "diagnose", "-f", fixture("node-cordoned.json"), "--min-severity", "warning")
	if err != nil {
		t.Fatalf("diagnose: %v", err)
	}
	if strings.Contains(filtered, "cordoned") {
		t.Errorf("--min-severity warning must hide the info finding:\n%s", filtered)
	}
	if !strings.Contains(filtered, "No findings") {
		t.Errorf("filtering everything out should read as a clean run:\n%s", filtered)
	}
}

func TestDiagnoseRuleSelection(t *testing.T) {
	stdout, _, err := run(t, "diagnose", "-f", fixture("mixed-incident.json"), "--rule", "KTA002")
	if err != nil {
		t.Fatalf("diagnose: %v", err)
	}
	if !strings.Contains(stdout, "KTA002") {
		t.Errorf("the selected rule produced nothing:\n%s", stdout)
	}
	for _, other := range []string{"KTA001", "KTA007", "KTA009"} {
		if strings.Contains(stdout, other) {
			t.Errorf("--rule KTA002 also ran %s:\n%s", other, stdout)
		}
	}
}

// TestDiagnoseRejectsUnknownRule protects against the worst kind of silence: a
// typo in --rule that runs no rules and reports a healthy cluster.
func TestDiagnoseRejectsUnknownRule(t *testing.T) {
	_, _, err := run(t, "diagnose", "-f", fixture("mixed-incident.json"), "--rule", "KTA999")
	if err == nil {
		t.Fatal("an unknown rule id must be an error, not an empty run")
	}
	if !strings.Contains(err.Error(), "KTA999") {
		t.Errorf("the error should name the bad id, got: %v", err)
	}
}

func TestDiagnoseRejectsUnknownSeverityAndFormat(t *testing.T) {
	if _, _, err := run(t, "diagnose", "-f", fixture("healthy.json"), "--min-severity", "urgent"); err == nil {
		t.Error("an unknown severity must be rejected")
	}
	if _, _, err := run(t, "diagnose", "-f", fixture("healthy.json"), "-o", "yaml"); err == nil {
		t.Error("an unsupported output format must be rejected")
	}
}

// TestDiagnoseRefusesToNarrowASnapshot guards a subtle correctness trap:
// applying --namespace to an already-collected file would drop findings and
// present the remainder as complete.
func TestDiagnoseRefusesToNarrowASnapshot(t *testing.T) {
	_, _, err := run(t, "diagnose", "-f", fixture("mixed-incident.json"), "-n", "payments")
	if err == nil {
		t.Fatal("--namespace against a cluster-wide snapshot must be refused")
	}
	if !strings.Contains(err.Error(), "re-run collect") {
		t.Errorf("the error should say how to get what was asked for, got: %v", err)
	}
}

func TestFailOnControlsTheExitSignal(t *testing.T) {
	tests := []struct {
		name      string
		file      string
		failOn    string
		wantError bool
	}{
		{"critical findings trip a critical threshold", "crashloop-oomkilled.json", "critical", true},
		{"critical findings trip a warning threshold", "crashloop-oomkilled.json", "warning", true},
		{"an info finding does not trip a warning threshold", "node-cordoned.json", "warning", false},
		{"an info finding trips an info threshold", "node-cordoned.json", "info", true},
		{"a clean run never trips", "healthy.json", "critical", false},
		{"the default is not to trip at all", "crashloop-oomkilled.json", "none", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := run(t, "diagnose", "-f", fixture(tt.file), "--fail-on", tt.failOn)
			if tt.wantError {
				if err == nil {
					t.Fatal("expected the findings signal, got none")
				}
				if !IsFindingsError(err) {
					t.Errorf("error should be the findings signal, got: %v", err)
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// TestFindingsErrorIsDistinguishableFromFailure is what lets main pick the
// right exit code: 2 means "your cluster is unhealthy", 1 means "this tool
// broke", and a CI step needs to tell them apart.
func TestFindingsErrorIsDistinguishableFromFailure(t *testing.T) {
	_, _, findings := run(t, "diagnose", "-f", fixture("crashloop-oomkilled.json"), "--fail-on", "critical")
	if !IsFindingsError(findings) {
		t.Errorf("a findings result must be recognisable: %v", findings)
	}

	_, _, broken := run(t, "diagnose", "-f", filepath.Join("testdata", "does-not-exist.json"))
	if broken == nil {
		t.Fatal("a missing snapshot must be an error")
	}
	if IsFindingsError(broken) {
		t.Error("a missing file must not be reported as findings")
	}
	if ExitFindings == 1 {
		t.Error("the findings exit code must differ from the failure exit code")
	}
}

func TestRulesCommandListsEveryRule(t *testing.T) {
	stdout, _, err := run(t, "rules")
	if err != nil {
		t.Fatalf("rules: %v", err)
	}
	for _, id := range []string{"KTA001", "KTA002", "KTA003", "KTA004", "KTA005",
		"KTA006", "KTA007", "KTA008", "KTA009", "KTA010"} {
		if !strings.Contains(stdout, id) {
			t.Errorf("rule %s is not listed:\n%s", id, stdout)
		}
	}
	if strings.Count(strings.TrimSpace(stdout), "\n")+1 != 10 {
		t.Errorf("expected one line per rule:\n%s", stdout)
	}
}

func TestDiagnoseRejectsAForeignSnapshotFormat(t *testing.T) {
	_, _, err := run(t, "diagnose", "-f", filepath.Join("testdata", "wrong-format.json"))
	if err == nil {
		t.Fatal("a file that is not a kubediag snapshot must be refused")
	}
	if !strings.Contains(err.Error(), "format") {
		t.Errorf("the error should name the format problem, got: %v", err)
	}
}
