// Command kubediag diagnoses unhealthy Kubernetes workloads and explains the
// cause in plain language.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/lpogosu/k8s-troubleshoot-agent/internal/cli"
)

// version is stamped in at build time; see the Makefile.
var version = "dev"

// main does nothing but translate the run into an exit code. The work lives in
// run so that its deferred signal handler actually runs — os.Exit skips
// defers, and a signal context left registered is a real leak in a tool that
// may be invoked in a loop from a script.
func main() {
	os.Exit(run())
}

func run() int {
	cli.SetVersion(version)

	// Ctrl-C must cancel an in-flight collection rather than leave a request
	// hanging against an API server that is already struggling.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	root := cli.NewRootCommand(os.Stdout, os.Stderr)
	err := root.ExecuteContext(ctx)
	switch {
	case err == nil:
		return 0
	case cli.IsFindingsError(err):
		// Not a failure of the tool: the cluster is unhealthy and --fail-on
		// asked to say so in the exit code.
		return cli.ExitFindings
	default:
		fmt.Fprintln(os.Stderr, "kubediag:", err)
		return 1
	}
}
