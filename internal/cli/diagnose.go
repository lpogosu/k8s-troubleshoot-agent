package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/lpogosu/k8s-troubleshoot-agent/internal/collect"
	"github.com/lpogosu/k8s-troubleshoot-agent/internal/report"
	"github.com/lpogosu/k8s-troubleshoot-agent/internal/rules"
	"github.com/lpogosu/k8s-troubleshoot-agent/internal/snapshot"
)

// ExitFindings is returned when --fail-on is satisfied. It is 2 rather than 1
// so a CI step can tell "the cluster is unhealthy" apart from "the tool itself
// failed", which exits 1.
const ExitFindings = 2

// findingsError signals that the run succeeded but produced findings at or
// above the --fail-on threshold.
type findingsError struct{ worst rules.Severity }

func (e findingsError) Error() string {
	return fmt.Sprintf("findings at severity %s or above", e.worst)
}

// IsFindingsError reports whether an error is the --fail-on signal rather than
// a real failure. main uses it to pick the exit code.
func IsFindingsError(err error) bool {
	var target findingsError
	return errors.As(err, &target)
}

func newDiagnoseCommand(global *globalFlags, stdout, stderr io.Writer) *cobra.Command {
	var (
		file        string
		format      string
		minSeverity string
		selected    []string
		failOn      string
	)

	cmd := &cobra.Command{
		Use:   "diagnose",
		Short: "Explain what is broken, from a live cluster or a snapshot",
		Long: "diagnose runs every rule over a cluster snapshot and prints what is wrong, the\n" +
			"evidence each conclusion rests on, and the command to run next.\n\n" +
			"With --file it reads a snapshot written by `kubediag collect`; without it, it\n" +
			"collects from the current context first. The rules cannot tell the difference,\n" +
			"which is what makes them testable.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			min, err := rules.ParseSeverity(minSeverity)
			if err != nil {
				return err
			}

			engine := rules.NewDefaultEngine()
			if len(selected) > 0 {
				var unknown []string
				engine, unknown = rules.Select(selected)
				if len(unknown) > 0 {
					return fmt.Errorf("unknown rule id(s): %s (see `kubediag rules`)", strings.Join(unknown, ", "))
				}
			}

			snap, err := loadSnapshot(cmd.Context(), global, file, stderr)
			if err != nil {
				return err
			}

			findings := engine.Run(snap)
			kept := findings[:0]
			for _, f := range findings {
				if f.Severity.AtLeast(min) {
					kept = append(kept, f)
				}
			}

			rep := report.Build(snap, engine, kept)
			switch format {
			case "json":
				err = report.WriteJSON(stdout, rep)
			case "text":
				err = report.WriteText(stdout, rep)
			default:
				return fmt.Errorf("unknown output format %q (want text or json)", format)
			}
			if err != nil {
				return err
			}

			return failOnSeverity(rep, failOn)
		},
	}

	f := cmd.Flags()
	f.StringVarP(&file, "file", "f", "", `snapshot to diagnose, or "-" for stdin (default: collect from the cluster)`)
	f.StringVarP(&format, "output", "o", "text", "output format: text or json")
	f.StringVar(&minSeverity, "min-severity", "info", "hide findings below this severity: critical, warning or info")
	f.StringSliceVar(&selected, "rule", nil, "run only these rule ids (repeatable, comma-separated)")
	f.StringVar(&failOn, "fail-on", "none",
		"exit with code 2 when a finding at this severity or above is reported: critical, warning, info or none")
	return cmd
}

func loadSnapshot(ctx context.Context, global *globalFlags, file string, stderr io.Writer) (*snapshot.Snapshot, error) {
	if file != "" {
		snap, err := snapshot.Load(file)
		if err != nil {
			return nil, err
		}
		// A snapshot was collected with its own namespace scope. Narrowing it
		// further at diagnose time would silently drop findings, so the flag
		// is refused rather than half-applied.
		if global.namespace != "" && global.namespace != snap.Source.Namespace {
			return nil, fmt.Errorf(
				"--namespace %s cannot be applied to a snapshot collected with scope %q; "+
					"re-run collect with the namespace you want",
				global.namespace, scopeName(snap.Source.Namespace))
		}
		return snap, nil
	}

	collector, err := collect.New(collect.Options{
		Namespace:  global.namespace,
		Kubeconfig: global.kubeconfig,
		Context:    global.context,
	})
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, collect.DefaultTimeout)
	defer cancel()

	snap, errs := collector.Collect(ctx)
	printErrors(stderr, "warning", errs)
	return snap, nil
}

func scopeName(ns string) string {
	if ns == "" {
		return "all namespaces"
	}
	return ns
}

func failOnSeverity(rep *report.Report, failOn string) error {
	if failOn == "none" || failOn == "" {
		return nil
	}
	threshold, err := rules.ParseSeverity(failOn)
	if err != nil {
		return err
	}
	worst, ok := rep.Worst()
	if ok && worst.AtLeast(threshold) {
		return findingsError{worst: worst}
	}
	return nil
}
