package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/lpogosu/k8s-troubleshoot-agent/internal/rules"
	"github.com/lpogosu/k8s-troubleshoot-agent/internal/snapshot"
)

// wrapWidth is the column the prose is wrapped at. Fixed rather than read from
// the terminal so that piping the output into a file or a pull request comment
// produces the same bytes as reading it on screen.
const wrapWidth = 88

// WriteText renders the report for a human.
//
// No colour and no box-drawing: this output is pasted into tickets and chat
// far more often than it is admired in a terminal, and escape codes survive
// neither.
func WriteText(w io.Writer, r *Report) error {
	b := &strings.Builder{}

	fmt.Fprintf(b, "kubediag · %s\n", sourceLine(r))
	// The inventory line is wrapped like prose: with nine object kinds it is
	// longer than most of the findings underneath it.
	b.WriteString(wrap("scanned: "+r.Scanned.describe(), wrapWidth) + "\n")

	if len(r.Findings) == 0 {
		b.WriteString("\nNo findings. Every rule ran and none matched.\n")
		b.WriteString("This means nothing the rules cover is broken — it is not a statement that the\n")
		b.WriteString("cluster is healthy. Rules cover: see `kubediag rules`.\n")
		_, err := io.WriteString(w, b.String())
		return err
	}

	fmt.Fprintf(b, "findings: %s\n", severityLine(r))

	for i, f := range r.Findings {
		b.WriteString("\n")
		fmt.Fprintf(b, "%s  %s\n", severityLabel(f.Severity), f.Title)
		fmt.Fprintf(b, "  %s · %s\n", f.Subject.String(), f.RuleID)
		b.WriteString("\n")
		b.WriteString(indent(wrap(f.Summary, wrapWidth-2), "  "))

		b.WriteString("\n  evidence\n")
		for _, e := range f.Evidence {
			b.WriteString(renderEvidence(e))
		}

		if len(f.NextSteps) > 0 {
			b.WriteString("\n  next\n")
			for _, s := range f.NextSteps {
				fmt.Fprintf(b, "    $ %s\n", s)
			}
		}
		if i < len(r.Findings)-1 {
			b.WriteString("\n" + strings.Repeat("-", wrapWidth) + "\n")
		}
	}

	_, err := io.WriteString(w, b.String())
	return err
}

func renderEvidence(e rules.Evidence) string {
	head := fmt.Sprintf("    %s  %s", evidenceMarker(e.Kind), e.Source)
	if e.Count > 1 {
		head += fmt.Sprintf(" (x%d)", e.Count)
	}
	if e.ObservedAt != nil {
		head += "  " + snapshot.FormatTime(*e.ObservedAt)
	}
	body := indent(wrap(e.Detail, wrapWidth-8), "        ")
	return head + "\n" + body
}

// evidenceMarker is a fixed-width tag rather than an icon, so evidence lines
// align and can be grepped by kind.
func evidenceMarker(k rules.EvidenceKind) string {
	switch k {
	case rules.EvidenceEvent:
		return "[event]"
	case rules.EvidenceCondition:
		return "[cond] "
	default:
		return "[field]"
	}
}

func severityLabel(s rules.Severity) string {
	switch s {
	case rules.SeverityCritical:
		return "CRITICAL"
	case rules.SeverityWarning:
		return "WARNING "
	default:
		return "INFO    "
	}
}

func severityLine(r *Report) string {
	order := []rules.Severity{rules.SeverityCritical, rules.SeverityWarning, rules.SeverityInfo}
	var parts []string
	for _, s := range order {
		if n := r.Summary[string(s)]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, s))
		}
	}
	return strings.Join(parts, ", ")
}

func sourceLine(r *Report) string {
	scope := "all namespaces"
	if r.Source.Namespace != "" {
		scope = "namespace " + r.Source.Namespace
	}
	where := r.Source.Context
	if where == "" {
		where = "snapshot"
	}
	return fmt.Sprintf("%s · %s · captured %s", where, scope, snapshot.FormatTime(r.CapturedAt))
}

// wrap breaks text at word boundaries. A word longer than the width — a long
// image reference or a jsonpath — is left intact rather than split, because
// breaking it would make it uncopyable.
func wrap(text string, width int) string {
	var lines []string
	for _, paragraph := range strings.Split(text, "\n") {
		words := strings.Fields(paragraph)
		if len(words) == 0 {
			lines = append(lines, "")
			continue
		}
		line := words[0]
		for _, word := range words[1:] {
			if len([]rune(line))+1+len([]rune(word)) > width {
				lines = append(lines, line)
				line = word
				continue
			}
			line += " " + word
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

func indent(text, prefix string) string {
	lines := strings.Split(text, "\n")
	for i, l := range lines {
		if l == "" {
			continue
		}
		lines[i] = prefix + l
	}
	return strings.Join(lines, "\n") + "\n"
}
