package cli

import (
	"context"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/lpogosu/k8s-troubleshoot-agent/internal/collect"
)

func newCollectCommand(global *globalFlags, stdout, stderr io.Writer) *cobra.Command {
	var (
		output        string
		keepEnvValues bool
	)

	cmd := &cobra.Command{
		Use:   "collect",
		Short: "Write the current cluster state to a snapshot file",
		Long: "collect reads the cluster once, read-only, and writes everything the rules need to a\n" +
			"single JSON file.\n\n" +
			"The file is the unit of exchange: it can be attached to a ticket, replayed by\n" +
			"`kubediag diagnose -f`, and diffed against a snapshot taken before the incident.\n" +
			"Literal values of container environment variables are replaced with a placeholder\n" +
			"before writing, because pod specs routinely carry credentials and a snapshot is made\n" +
			"to be sent to other people. Pass --keep-env-values to disable that.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			collector, err := collect.New(collect.Options{
				Namespace:     global.namespace,
				Kubeconfig:    global.kubeconfig,
				Context:       global.context,
				KeepEnvValues: keepEnvValues,
			})
			if err != nil {
				return err
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), collect.DefaultTimeout)
			defer cancel()

			snap, errs := collector.Collect(ctx)
			printErrors(stderr, "warning", errs)

			if output == "-" {
				return snap.Write(stdout)
			}
			if err := snap.Save(output); err != nil {
				return err
			}
			fmt.Fprintf(stdout, "wrote %s: %d pods, %d events, %d nodes from context %q\n",
				output, len(snap.Pods), len(snap.Events), len(snap.Nodes), snap.Source.Context)
			return nil
		},
	}

	cmd.Flags().StringVarP(&output, "output", "o", "snapshot.json", `file to write, or "-" for stdout`)
	cmd.Flags().BoolVar(&keepEnvValues, "keep-env-values", false,
		"keep literal env values in the snapshot (they are redacted by default)")
	return cmd
}
