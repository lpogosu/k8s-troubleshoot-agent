package rules_test

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/lpogosu/k8s-troubleshoot-agent/internal/rules"
	"github.com/lpogosu/k8s-troubleshoot-agent/internal/snapshot"
)

// want is one expected finding, identified by the pair that must be unique in
// a report: which rule fired, and about what.
type want struct {
	rule     string
	subject  string
	severity rules.Severity
	// titleContains is checked when set. It is how the sub-classification
	// inside a rule is pinned: KTA001 firing is not the interesting part,
	// KTA001 saying "wrong tag" rather than "no credentials" is.
	titleContains string
	// summaryContains pins a claim the summary must make. Used where the
	// distinction between two causes lives in the prose rather than the title.
	summaryContains string
	// evidenceContains pins a piece of evidence the finding must cite, so a
	// rule cannot pass by asserting the right thing for the wrong reason.
	evidenceContains string
}

// fixtureCase describes what a snapshot must and must not produce.
//
// wantFindings is exhaustive: any finding not listed fails the test. That is
// deliberate — a rule engine is judged as much by what it stays quiet about as
// by what it catches, and an "at least these" assertion would let false
// positives accumulate unnoticed.
type fixtureCase struct {
	file string
	// why explains what the fixture represents, so a failure is readable
	// without opening the JSON.
	why          string
	wantFindings []want
	// mustNotFire lists rules that a careless implementation would trip on
	// this input. Redundant with the exhaustive match above, and kept because
	// it records the intent: these are the traps, not just absences.
	mustNotFire []string
}

func TestRulesAgainstFixtures(t *testing.T) {
	cases := []fixtureCase{
		{
			file: "imagepull-wrong-tag.json",
			why:  "registry answered and has no such tag",
			wantFindings: []want{{
				rule:             "KTA001",
				subject:          "shop/pod/checkout-7d9c8b5f4-lm2xq [app]",
				severity:         rules.SeverityCritical,
				titleContains:    "does not exist in the registry",
				evidenceContains: "not found",
			}},
			// The pod is Pending, but it has a node: the scheduler did its job.
			mustNotFire: []string{"KTA003", "KTA004"},
		},
		{
			file: "imagepull-no-credentials.json",
			why:  "private registry rejected an anonymous pull",
			wantFindings: []want{{
				rule:            "KTA001",
				subject:         "billing/pod/api-6f4b8d7c9-2hqzt [app]",
				severity:        rules.SeverityCritical,
				titleContains:   "credentials rejected",
				summaryContains: "no imagePullSecrets at all",
			}},
			mustNotFire: []string{"KTA003"},
		},
		{
			file: "imagepull-rate-limited.json",
			why:  "Docker Hub returned 429, which is not a workload fault at all",
			wantFindings: []want{{
				rule:            "KTA001",
				subject:         "cache/pod/redis-5c7d9f8b4-xn4rp [app]",
				severity:        rules.SeverityCritical,
				titleContains:   "rate-limiting",
				summaryContains: "Nothing about the workload is wrong",
			}},
		},
		{
			file: "crashloop-oomkilled.json",
			why:  "exit 137 with reason OOMKilled is the container's own memory limit",
			wantFindings: []want{{
				rule:             "KTA002",
				subject:          "payments/pod/ledger-5f8c7d6b9-4kq2n [app]",
				severity:         rules.SeverityCritical,
				titleContains:    "OOM-killed",
				summaryContains:  "The limit in force is 128Mi",
				evidenceContains: "exitCode=137",
			}},
			// The pod is Running and not Ready, which is exactly the shape
			// KTA006 looks for. It must defer: the container is not running,
			// it is waiting in backoff, and KTA002 already explains why.
			mustNotFire: []string{"KTA006"},
		},
		{
			file: "crashloop-app-exit.json",
			why:  "exit 1 is the application's own error path, not infrastructure",
			wantFindings: []want{{
				rule:            "KTA002",
				subject:         "notify/pod/dispatcher-5f8c7d6b9-9wm7c [app]",
				severity:        rules.SeverityCritical,
				titleContains:   "application exits with code 1",
				summaryContains: "application-level failure",
			}},
			mustNotFire: []string{"KTA006"},
		},
		{
			file: "crashloop-liveness-sigkill.json",
			why:  "exit 137 without OOMKilled is a signal from outside the container",
			wantFindings: []want{{
				rule:            "KTA002",
				subject:         "search/pod/indexer-5f8c7d6b9-t8bkq [app]",
				severity:        rules.SeverityCritical,
				titleContains:   "killed with SIGKILL",
				summaryContains: "rules out the container's own memory limit",
			}},
		},
		{
			file: "pending-insufficient-cpu.json",
			why:  "the pod asks for more CPU than any node has unreserved",
			wantFindings: []want{{
				rule:             "KTA003",
				subject:          "batch/pod/trainer-6d8c9f7b5-r4zjq",
				severity:         rules.SeverityCritical,
				titleContains:    "enough free CPU",
				summaryContains:  "not against current usage",
				evidenceContains: "cpu=4",
			}},
			mustNotFire: []string{"KTA004"},
		},
		{
			file: "pending-untolerated-taint.json",
			why:  "every node refuses the pod, so adding capacity cannot help",
			wantFindings: []want{{
				rule:             "KTA003",
				subject:          "web/pod/frontend-7c5d8b6f9-mp3xw",
				severity:         rules.SeverityCritical,
				titleContains:    "taint the pod does not tolerate",
				evidenceContains: "workload=batch:NoSchedule",
			}},
		},
		{
			file: "pending-node-selector.json",
			why:  "nodeSelector asks for a label no node carries",
			wantFindings: []want{{
				rule:             "KTA003",
				subject:          "storage/pod/chunker-8f9c7d6b5-kv2ln",
				severity:         rules.SeverityCritical,
				titleContains:    "no node matches the pod's node selector",
				evidenceContains: "disktype=nvme",
			}},
		},
		{
			file: "pending-unbound-pvc.json",
			why:  "one missing StorageClass blocks both the claim and the pod",
			wantFindings: []want{
				{
					rule:            "KTA003",
					subject:         "reporting/pod/warehouse-0",
					severity:        rules.SeverityCritical,
					titleContains:   "waiting for a PersistentVolumeClaim",
					summaryContains: "irrelevant until the storage side is resolved",
				},
				{
					rule:             "KTA005",
					subject:          "reporting/persistentvolumeclaim/warehouse-data",
					severity:         rules.SeverityCritical,
					titleContains:    "StorageClass that does not exist",
					evidenceContains: "fast-ssd",
				},
			},
		},
		{
			file: "stuck-missing-configmap.json",
			why:  "scheduled but the kubelet cannot mount a ConfigMap that is absent",
			wantFindings: []want{{
				rule:             "KTA004",
				subject:          "edge/pod/gateway-9d7c8b6f5-qw8tz",
				severity:         rules.SeverityCritical,
				titleContains:    "ConfigMap the pod mounts does not exist",
				evidenceContains: "gateway-config",
			}},
			// The pod is Pending, but scheduling succeeded, so the scheduling
			// rule must stay out of it.
			mustNotFire: []string{"KTA003"},
		},
		{
			file: "stuck-missing-secret.json",
			why:  "same shape as the ConfigMap case but a different object and fix",
			wantFindings: []want{{
				rule:            "KTA004",
				subject:         "jobs/pod/worker-4b8f9c7d6-h2vnl",
				severity:        rules.SeverityCritical,
				titleContains:   "Secret the pod mounts does not exist",
				summaryContains: "no restart is needed",
			}},
			mustNotFire: []string{"KTA003"},
		},
		{
			file: "readiness-connection-refused.json",
			why:  "nothing listens on the probe port, so the whole Service is dark",
			wantFindings: []want{
				{
					rule:            "KTA010",
					subject:         "search/deployment/query-api",
					severity:        rules.SeverityCritical,
					titleContains:   "Deployment has not converged",
					summaryContains: "progressDeadlineSeconds",
				},
				{
					rule:            "KTA006",
					subject:         "search/pod/query-api-6b8f9c7d5-2n8xk [api]",
					severity:        rules.SeverityCritical,
					titleContains:   "never becomes ready",
					summaryContains: "nothing is listening on that port",
				},
				{
					rule:          "KTA006",
					subject:       "search/pod/query-api-6b8f9c7d5-vt4qc [api]",
					severity:      rules.SeverityCritical,
					titleContains: "never becomes ready",
				},
				{
					rule:            "KTA007",
					subject:         "search/service/query-api",
					severity:        rules.SeverityCritical,
					titleContains:   "endpoints but none is ready",
					summaryContains: "2 pod(s) match the selector",
				},
			},
			mustNotFire: []string{"KTA002"},
		},
		{
			file: "service-selector-typo.json",
			why:  "pods are healthy; the Service selector says app=web and they are app=webapp",
			wantFindings: []want{{
				rule:             "KTA007",
				subject:          "storefront/service/web",
				severity:         rules.SeverityCritical,
				titleContains:    "matches no pod",
				evidenceContains: "app=webapp",
			}},
			// Both pods are Running and Ready and the Deployment is complete;
			// only the Service is wrong.
			mustNotFire: []string{"KTA002", "KTA006", "KTA010"},
		},
		{
			file: "quota-exhausted.json",
			why:  "admission rejects new pods, and the symptom appears on the Deployment",
			wantFindings: []want{
				{
					rule:             "KTA008",
					subject:          "analytics/resourcequota/team-quota",
					severity:         rules.SeverityCritical,
					titleContains:    "is exhausted",
					summaryContains:  "the pod is never created",
					evidenceContains: "pods used=10 hard=10",
				},
				{
					rule:            "KTA010",
					subject:         "analytics/deployment/etl-worker",
					severity:        rules.SeverityWarning,
					summaryContains: "there is no pod",
				},
			},
		},
		{
			file: "node-notready.json",
			why:  "the kubelet went silent; pod status on that node is stale, not wrong",
			wantFindings: []want{{
				rule:             "KTA009",
				subject:          "node/diag-worker2",
				severity:         rules.SeverityCritical,
				titleContains:    "node is not Ready",
				summaryContains:  "Network, not workload",
				evidenceContains: "streaming/kafka-0",
			}},
			// The pods on the dead node still report Running and Ready. No pod
			// rule may invent a fault from that.
			mustNotFire: []string{"KTA002", "KTA006", "KTA007"},
		},
		{
			file: "node-disk-pressure.json",
			why:  "the node is evicting; the evicted pod is a symptom, not a crash",
			wantFindings: []want{{
				rule:             "KTA009",
				subject:          "node/diag-worker",
				severity:         rules.SeverityWarning,
				titleContains:    "disk pressure",
				evidenceContains: "observability/logs-shipper-8c7d9f6b5-r2knp",
			}},
			mustNotFire: []string{"KTA002"},
		},
		{
			file: "node-cordoned.json",
			why:  "cordoning is deliberate, so it is reported as context rather than a fault",
			wantFindings: []want{{
				rule:          "KTA009",
				subject:       "node/diag-worker2",
				severity:      rules.SeverityInfo,
				titleContains: "cordoned",
			}},
		},
		{
			file:         "healthy.json",
			why:          "a working cluster must produce exactly nothing",
			wantFindings: nil,
			mustNotFire: []string{
				"KTA001", "KTA002", "KTA003", "KTA004", "KTA005",
				"KTA006", "KTA007", "KTA008", "KTA009", "KTA010",
			},
		},
		{
			file:         "rollout-in-progress.json",
			why:          "a deployment 18 seconds old is starting, not failing",
			wantFindings: nil,
			// Every one of these would fire without a start-up grace, and this
			// is the case that decides whether the tool is usable during a
			// normal working day.
			mustNotFire: []string{"KTA004", "KTA005", "KTA006", "KTA007", "KTA010"},
		},
		{
			file:         "completed-jobs.json",
			why:          "a finished Job and a failed Job pod belong to the Job, not to us",
			wantFindings: nil,
			mustNotFire:  []string{"KTA002", "KTA006"},
		},
		{
			file:         "terminating.json",
			why:          "objects being deleted were asked to go; reporting them is noise",
			wantFindings: nil,
			mustNotFire:  []string{"KTA002", "KTA005", "KTA006", "KTA007"},
		},
		{
			file: "mixed-incident.json",
			why:  "several unrelated faults at once, to pin severity ordering",
			wantFindings: []want{
				{rule: "KTA001", subject: "shop/pod/checkout-7d9c8b5f4-lm2xq [app]", severity: rules.SeverityCritical},
				{rule: "KTA009", subject: "node/diag-worker2", severity: rules.SeverityCritical},
				{rule: "KTA002", subject: "payments/pod/ledger-5f8c7d6b9-4kq2n [app]", severity: rules.SeverityCritical},
				{rule: "KTA010", subject: "search/deployment/query-api", severity: rules.SeverityCritical},
				{rule: "KTA006", subject: "search/pod/query-api-6b8f9c7d5-2n8xk [api]", severity: rules.SeverityCritical},
				{rule: "KTA007", subject: "search/service/query-api", severity: rules.SeverityCritical},
				{rule: "KTA009", subject: "node/diag-worker", severity: rules.SeverityWarning},
				{rule: "KTA008", subject: "search/resourcequota/search-quota", severity: rules.SeverityWarning},
			},
		},
	}

	engine := rules.NewDefaultEngine()

	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			snap := loadFixture(t, tc.file)
			findings := engine.Run(snap)

			assertExactFindings(t, tc, findings)
			assertRulesSilent(t, tc.mustNotFire, findings)
		})
	}
}

// assertExactFindings checks that the findings are exactly the expected set,
// matched on (rule, subject), and that each one makes the claim it is supposed
// to make.
func assertExactFindings(t *testing.T, tc fixtureCase, got []rules.Finding) {
	t.Helper()

	byKey := make(map[string]rules.Finding, len(got))
	for _, f := range got {
		key := f.RuleID + " " + f.Subject.String()
		if _, dup := byKey[key]; dup {
			t.Errorf("rule %s reported %s twice; a finding must be unique per subject",
				f.RuleID, f.Subject)
		}
		byKey[key] = f
	}

	for _, w := range tc.wantFindings {
		key := w.rule + " " + w.subject
		f, ok := byKey[key]
		if !ok {
			t.Errorf("missing finding %q\n  fixture: %s\n  got:     %s", key, tc.why, keysOf(byKey))
			continue
		}
		delete(byKey, key)

		if f.Severity != w.severity {
			t.Errorf("%s: severity = %q, want %q", key, f.Severity, w.severity)
		}
		if w.titleContains != "" && !strings.Contains(f.Title, w.titleContains) {
			t.Errorf("%s: title = %q, want it to contain %q", key, f.Title, w.titleContains)
		}
		if w.summaryContains != "" && !strings.Contains(f.Summary, w.summaryContains) {
			t.Errorf("%s: summary does not contain %q\n  summary: %s", key, w.summaryContains, f.Summary)
		}
		if w.evidenceContains != "" && !evidenceMentions(f, w.evidenceContains) {
			t.Errorf("%s: no evidence mentions %q\n  evidence: %s",
				key, w.evidenceContains, evidenceDump(f))
		}
	}

	for key, f := range byKey {
		t.Errorf("unexpected finding %q (%s)\n  fixture: %s\n  summary: %s",
			key, f.Severity, tc.why, f.Summary)
	}
}

func assertRulesSilent(t *testing.T, silent []string, got []rules.Finding) {
	t.Helper()
	for _, id := range silent {
		for _, f := range got {
			if f.RuleID == id {
				t.Errorf("rule %s must not fire here but reported %q on %s",
					id, f.Title, f.Subject)
			}
		}
	}
}

// TestFindingsAreOrderedBySeverity pins the reading order: the worst thing
// first. An operator scanning the top of the output must not have to read past
// a cordoned node to reach an outage.
func TestFindingsAreOrderedBySeverity(t *testing.T) {
	snap := loadFixture(t, "mixed-incident.json")
	findings := rules.NewDefaultEngine().Run(snap)

	if len(findings) < 2 {
		t.Fatalf("fixture produced %d findings, expected several", len(findings))
	}
	for i := 1; i < len(findings); i++ {
		prev, cur := findings[i-1], findings[i]
		if cur.Severity.Rank() < prev.Severity.Rank() {
			t.Errorf("finding %d (%s) is more severe than the one before it (%s)",
				i, cur.Severity, prev.Severity)
		}
	}
}

// TestEveryFindingCitesEvidence enforces the contract the whole tool rests on:
// nothing is asserted that the reader cannot go and check.
func TestEveryFindingCitesEvidence(t *testing.T) {
	for _, file := range allFixtures(t) {
		snap := loadFixture(t, file)
		for _, f := range rules.NewDefaultEngine().Run(snap) {
			if len(f.Evidence) == 0 {
				t.Errorf("%s: finding %s on %s cites no evidence", file, f.RuleID, f.Subject)
			}
			for _, e := range f.Evidence {
				if strings.TrimSpace(e.Source) == "" {
					t.Errorf("%s: %s on %s has evidence with no source", file, f.RuleID, f.Subject)
				}
			}
			if strings.TrimSpace(f.Summary) == "" {
				t.Errorf("%s: finding %s on %s has an empty summary", file, f.RuleID, f.Subject)
			}
			if f.Severity.Rank() >= 3 {
				t.Errorf("%s: finding %s has unknown severity %q", file, f.RuleID, f.Severity)
			}
		}
	}
}

// TestRunIsDeterministic guards the property that makes snapshots useful: the
// same file must always produce byte-identical findings, whatever order the
// maps inside happened to iterate in.
func TestRunIsDeterministic(t *testing.T) {
	for _, file := range allFixtures(t) {
		first := fingerprint(rules.NewDefaultEngine().Run(loadFixture(t, file)))
		for i := 0; i < 8; i++ {
			if got := fingerprint(rules.NewDefaultEngine().Run(loadFixture(t, file))); got != first {
				t.Fatalf("%s: run %d differs from the first run\n first: %s\n got:   %s",
					file, i, first, got)
			}
		}
	}
}

// TestSelectRunsOnlyTheChosenRule confirms that --rule narrows the engine
// rather than filtering the output, and that a typo is refused.
func TestSelectRunsOnlyTheChosenRule(t *testing.T) {
	snap := loadFixture(t, "mixed-incident.json")

	engine, unknown := rules.Select([]string{"KTA002"})
	if len(unknown) != 0 {
		t.Fatalf("unknown rule ids: %v", unknown)
	}
	for _, f := range engine.Run(snap) {
		if f.RuleID != "KTA002" {
			t.Errorf("selected KTA002 but got a finding from %s", f.RuleID)
		}
	}

	if _, unknown = rules.Select([]string{"KTA002", "KTA999"}); len(unknown) != 1 || unknown[0] != "KTA999" {
		t.Errorf("unknown rule ids = %v, want [KTA999]", unknown)
	}
}

// TestRuleIDsAreUniqueAndDescribed catches the copy-paste mistake of cloning a
// rule and forgetting to change its identifier, which would make --rule
// ambiguous and the JSON output misleading.
func TestRuleIDsAreUniqueAndDescribed(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range rules.All() {
		if seen[r.ID()] {
			t.Errorf("duplicate rule id %s", r.ID())
		}
		seen[r.ID()] = true
		if !strings.HasPrefix(r.ID(), "KTA") {
			t.Errorf("rule id %q does not follow the KTAnnn convention", r.ID())
		}
		if len(r.Description()) < 20 {
			t.Errorf("rule %s has a description too short to be useful: %q", r.ID(), r.Description())
		}
	}
}

// --- helpers ---------------------------------------------------------------

func loadFixture(t *testing.T, name string) *snapshot.Snapshot {
	t.Helper()
	s, err := snapshot.Load(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("load fixture %s: %v", name, err)
	}
	return s
}

func allFixtures(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir("testdata")
	if err != nil {
		t.Fatalf("read testdata: %v", err)
	}
	var out []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".json") {
			out = append(out, e.Name())
		}
	}
	if len(out) == 0 {
		t.Fatal("no fixtures found in testdata")
	}
	sort.Strings(out)
	return out
}

func fingerprint(findings []rules.Finding) string {
	parts := make([]string, 0, len(findings))
	for _, f := range findings {
		parts = append(parts, f.RuleID+"|"+f.Subject.String()+"|"+string(f.Severity)+"|"+f.Title)
	}
	return strings.Join(parts, "\n")
}

func evidenceMentions(f rules.Finding, needle string) bool {
	for _, e := range f.Evidence {
		if strings.Contains(e.Source, needle) || strings.Contains(e.Detail, needle) {
			return true
		}
	}
	return false
}

func evidenceDump(f rules.Finding) string {
	var b strings.Builder
	for _, e := range f.Evidence {
		b.WriteString("\n    " + e.Source + " => " + e.Detail)
	}
	return b.String()
}

func keysOf(m map[string]rules.Finding) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		return "(no findings)"
	}
	return "\n    " + strings.Join(keys, "\n    ")
}
