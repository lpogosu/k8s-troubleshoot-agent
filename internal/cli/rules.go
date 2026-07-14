package cli

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/lpogosu/k8s-troubleshoot-agent/internal/rules"
)

func newRulesCommand(stdout io.Writer) *cobra.Command {
	return &cobra.Command{
		Use:   "rules",
		Short: "List the rules and what each one detects",
		Long: "rules prints the full rule set.\n\n" +
			"The list is the honest scope of this tool: a clean `diagnose` means none of these\n" +
			"rules matched, not that the cluster is healthy.",
		Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			w := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
			for _, r := range rules.All() {
				if _, err := fmt.Fprintf(w, "%s\t%s\n", r.ID(), r.Description()); err != nil {
					return err
				}
			}
			return w.Flush()
		},
	}
}
