package rules

import (
	"sort"
	"time"

	"github.com/lpogosu/k8s-troubleshoot-agent/internal/snapshot"
)

// StartupGrace is how long a workload is allowed to be broken before the rules
// that can misfire on a healthy start-up will speak.
//
// The number is not arbitrary: a kubelet needs to pull an image, and the
// backoff that turns a first failure into CrashLoopBackOff starts at 10s and
// doubles. Below about half a minute, "restarting" and "starting" are the same
// observation, and a tool that cannot tell them apart trains people to ignore
// it. Rules that key off a state which is already terminal — a manifest that
// does not exist, a taint nothing tolerates — ignore the grace period, because
// waiting longer cannot change the answer.
const StartupGrace = 30 * time.Second

// Rule turns a snapshot into zero or more findings. Implementations must be
// pure: same snapshot in, same findings out, no clock, no network, no
// filesystem. That is the whole reason snapshots exist.
type Rule interface {
	// ID is the stable identifier used to select or suppress the rule.
	ID() string
	// Description is one line explaining what the rule detects.
	Description() string
	// Evaluate inspects the snapshot and returns findings.
	Evaluate(s *snapshot.Snapshot) []Finding
}

// All returns every rule, ordered by ID.
func All() []Rule {
	rules := []Rule{
		imagePullRule{},
		crashLoopRule{},
		unschedulableRule{},
		volumeMountRule{},
		unboundClaimRule{},
		readinessRule{},
		serviceEndpointsRule{},
		quotaRule{},
		nodeHealthRule{},
		rolloutRule{},
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID() < rules[j].ID() })
	return rules
}

// Engine runs a set of rules over a snapshot.
type Engine struct {
	rules []Rule
}

// NewEngine builds an engine from an explicit rule set.
func NewEngine(rules []Rule) *Engine { return &Engine{rules: rules} }

// NewDefaultEngine builds an engine with every rule enabled.
func NewDefaultEngine() *Engine { return NewEngine(All()) }

// Select returns an engine limited to the given rule IDs, and reports any ID
// that matched nothing — a typo in `--rule` must fail loudly rather than
// silently diagnose nothing and report a healthy cluster.
func Select(ids []string) (engine *Engine, unknown []string) {
	wanted := make(map[string]bool, len(ids))
	for _, id := range ids {
		wanted[id] = false
	}
	var selected []Rule
	for _, r := range All() {
		if _, ok := wanted[r.ID()]; ok {
			wanted[r.ID()] = true
			selected = append(selected, r)
		}
	}
	for id, matched := range wanted {
		if !matched {
			unknown = append(unknown, id)
		}
	}
	sort.Strings(unknown)
	return NewEngine(selected), unknown
}

// Rules exposes the configured rule set.
func (e *Engine) Rules() []Rule { return e.rules }

// Run evaluates every rule and returns the findings, sorted.
//
// A finding without evidence is dropped rather than reported: the contract of
// this tool is that everything it claims can be checked against the cluster,
// and a rule bug must not be allowed to break that quietly downstream.
func (e *Engine) Run(s *snapshot.Snapshot) []Finding {
	var out []Finding
	for _, r := range e.rules {
		for _, f := range r.Evaluate(s) {
			if len(f.Evidence) == 0 {
				continue
			}
			f.RuleID = r.ID()
			out = append(out, f)
		}
	}
	SortFindings(out)
	return out
}
