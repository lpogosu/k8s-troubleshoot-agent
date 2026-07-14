// Package cli wires the commands together.
package cli

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"
)

// version is overridden at build time via -ldflags.
var version = "dev"

// globalFlags are the connection settings shared by every command that can
// touch a cluster. They mirror kubectl's names deliberately: a troubleshooting
// tool that needs its own flag vocabulary is one more thing to remember at 3am.
type globalFlags struct {
	kubeconfig string
	context    string
	namespace  string
}

// NewRootCommand builds the command tree. Output streams are injected so the
// commands can be exercised in tests without touching the process's stdio.
func NewRootCommand(stdout, stderr io.Writer) *cobra.Command {
	global := &globalFlags{}

	root := &cobra.Command{
		Use:   "kubediag",
		Short: "Explain why Kubernetes workloads are unhealthy",
		Long: "kubediag reads a Kubernetes cluster read-only, or a snapshot file taken from one,\n" +
			"and explains what is broken: the fault, the evidence it rests on, and the command to\n" +
			"run next.\n\n" +
			"It is a rule engine over cluster state, not a language model. The same input always\n" +
			"produces the same output, and nothing leaves the machine.",
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       version,
	}
	root.SetOut(stdout)
	root.SetErr(stderr)

	pf := root.PersistentFlags()
	pf.StringVar(&global.kubeconfig, "kubeconfig", "", "path to the kubeconfig file (default: the usual kubectl resolution)")
	pf.StringVar(&global.context, "context", "", "kubeconfig context to use (default: the current context)")
	pf.StringVarP(&global.namespace, "namespace", "n", "", "limit to one namespace (default: all namespaces)")

	root.AddCommand(
		newCollectCommand(global, stdout, stderr),
		newDiagnoseCommand(global, stdout, stderr),
		newRulesCommand(stdout),
	)
	return root
}

// SetVersion is called from main with the version stamped into the binary.
func SetVersion(v string) {
	if v != "" {
		version = v
	}
}

func printErrors(w io.Writer, prefix string, errs []error) {
	for _, err := range errs {
		fmt.Fprintf(w, "%s: %v\n", prefix, err)
	}
}
