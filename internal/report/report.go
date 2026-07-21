// Package report renders findings for the two audiences this tool has: a
// person reading a terminal, and a program consuming JSON.
//
// Both come from the same Report value, so the JSON can never drift from what
// the text output claims.
package report

import (
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/lpogosu/k8s-troubleshoot-agent/internal/rules"
	"github.com/lpogosu/k8s-troubleshoot-agent/internal/snapshot"
)

// Report is one diagnosis run.
type Report struct {
	Tool       string          `json:"tool"`
	CapturedAt metav1.Time     `json:"capturedAt"`
	Source     snapshot.Source `json:"source"`
	Scanned    Counts          `json:"scanned"`
	RulesRun   []string        `json:"rulesRun"`
	Findings   []rules.Finding `json:"findings"`
	Summary    map[string]int  `json:"summary"`
}

// Counts records the size of the snapshot the rules saw. Without it a clean
// report is ambiguous: "no findings" and "no data" look identical.
type Counts struct {
	Pods                   int `json:"pods"`
	Events                 int `json:"events"`
	Deployments            int `json:"deployments"`
	StatefulSets           int `json:"statefulSets"`
	Nodes                  int `json:"nodes"`
	PersistentVolumeClaims int `json:"persistentVolumeClaims"`
	Services               int `json:"services"`
	EndpointSlices         int `json:"endpointSlices"`
	ResourceQuotas         int `json:"resourceQuotas"`
}

// Build assembles a report from a snapshot and the findings produced from it.
func Build(s *snapshot.Snapshot, engine *rules.Engine, findings []rules.Finding) *Report {
	ids := make([]string, 0, len(engine.Rules()))
	for _, r := range engine.Rules() {
		ids = append(ids, r.ID())
	}
	summary := map[string]int{
		string(rules.SeverityCritical): 0,
		string(rules.SeverityWarning):  0,
		string(rules.SeverityInfo):     0,
	}
	for _, f := range findings {
		summary[string(f.Severity)]++
	}
	return &Report{
		Tool:       "kubediag",
		CapturedAt: s.CapturedAt,
		Source:     s.Source,
		Scanned: Counts{
			Pods:                   len(s.Pods),
			Events:                 len(s.Events),
			Deployments:            len(s.Deployments),
			StatefulSets:           len(s.StatefulSets),
			Nodes:                  len(s.Nodes),
			PersistentVolumeClaims: len(s.PersistentVolumeClaims),
			Services:               len(s.Services),
			EndpointSlices:         len(s.EndpointSlices),
			ResourceQuotas:         len(s.ResourceQuotas),
		},
		RulesRun: ids,
		Findings: findings,
		Summary:  summary,
	}
}

// Worst returns the highest severity present, and false when there are no
// findings at all.
func (r *Report) Worst() (rules.Severity, bool) {
	if len(r.Findings) == 0 {
		return "", false
	}
	// Findings are sorted worst-first, so the head is the answer.
	return r.Findings[0].Severity, true
}

func (c Counts) describe() string {
	parts := []struct {
		n     int
		label string
	}{
		{c.Nodes, "nodes"},
		{c.Pods, "pods"},
		{c.Deployments, "deployments"},
		{c.StatefulSets, "statefulsets"},
		{c.Services, "services"},
		{c.PersistentVolumeClaims, "pvcs"},
		{c.ResourceQuotas, "quotas"},
		{c.Events, "events"},
	}
	var out []string
	for _, p := range parts {
		out = append(out, fmt.Sprintf("%d %s", p.n, p.label))
	}
	return strings.Join(out, ", ")
}
