// Package collect reads cluster state through client-go and turns it into a
// snapshot.
//
// Everything here is read-only: list and get, no writes, no exec, no logs. The
// tool is meant to be safe to run against production by someone who is already
// having a bad day, and the surest way to guarantee that is to have no code
// path that can mutate anything.
package collect

import (
	"context"
	"fmt"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/lpogosu/k8s-troubleshoot-agent/internal/snapshot"
)

// listLimit caps every list call. A cluster with fifty thousand pods would
// otherwise produce a snapshot nobody can open and a request the API server
// has to page through in one go.
const listLimit = 2000

// Options controls what a collection covers.
type Options struct {
	// Namespace limits the collection; empty means every namespace.
	Namespace string
	// Kubeconfig overrides the default kubeconfig resolution.
	Kubeconfig string
	// Context selects a kubeconfig context; empty uses the current one.
	Context string
	// KeepEnvValues disables redaction of container environment values.
	KeepEnvValues bool
}

// Collector reads a cluster.
type Collector struct {
	client  kubernetes.Interface
	options Options
	context string
	server  string
}

// New builds a collector from a kubeconfig, resolving it the same way kubectl
// does so that `kubediag` and `kubectl` always agree on which cluster they are
// pointed at.
func New(opts Options) (*Collector, error) {
	loading := clientcmd.NewDefaultClientConfigLoadingRules()
	if opts.Kubeconfig != "" {
		loading.ExplicitPath = opts.Kubeconfig
	}
	overrides := &clientcmd.ConfigOverrides{}
	if opts.Context != "" {
		overrides.CurrentContext = opts.Context
	}
	cc := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loading, overrides)

	raw, err := cc.RawConfig()
	if err != nil {
		return nil, fmt.Errorf("read kubeconfig: %w", err)
	}
	contextName := overrides.CurrentContext
	if contextName == "" {
		contextName = raw.CurrentContext
	}
	if contextName == "" {
		return nil, fmt.Errorf("no current context in kubeconfig: pass --context")
	}

	cfg, err := cc.ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("build client config: %w", err)
	}
	cfg.UserAgent = "kubediag"

	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("build kubernetes client: %w", err)
	}
	return &Collector{client: client, options: opts, context: contextName, server: cfg.Host}, nil
}

// NewWithClient builds a collector over an existing client, which is how the
// collector is exercised against a fake clientset in tests.
func NewWithClient(client kubernetes.Interface, opts Options) *Collector {
	return &Collector{client: client, options: opts, context: opts.Context}
}

// Collect gathers every resource kind the rules need.
//
// A failure on one kind does not abort the whole collection: a user with rights
// to read pods but not nodes should still get a usable snapshot, and the
// resulting empty list is visible in the report's `scanned` counts rather than
// being mistaken for a healthy cluster.
func (c *Collector) Collect(ctx context.Context) (*snapshot.Snapshot, []error) {
	ns := c.options.Namespace
	listOpts := metav1.ListOptions{Limit: listLimit}

	s := &snapshot.Snapshot{
		Format:     snapshot.Format,
		CapturedAt: metav1.Now(),
		Source: snapshot.Source{
			Context:   c.context,
			Server:    c.server,
			Namespace: ns,
		},
	}

	var errs []error
	record := func(kind string, err error) {
		if err != nil {
			errs = append(errs, fmt.Errorf("list %s: %w", kind, explain(err)))
		}
	}

	if v, err := c.client.Discovery().ServerVersion(); err == nil {
		s.Source.KubernetesVersion = v.GitVersion
	} else {
		record("server version", err)
	}

	pods, err := c.client.CoreV1().Pods(ns).List(ctx, listOpts)
	record("pods", err)
	if pods != nil {
		s.Pods = pods.Items
	}

	events, err := c.client.CoreV1().Events(ns).List(ctx, listOpts)
	record("events", err)
	if events != nil {
		s.Events = events.Items
	}

	deployments, err := c.client.AppsV1().Deployments(ns).List(ctx, listOpts)
	record("deployments", err)
	if deployments != nil {
		s.Deployments = deployments.Items
	}

	statefulSets, err := c.client.AppsV1().StatefulSets(ns).List(ctx, listOpts)
	record("statefulsets", err)
	if statefulSets != nil {
		s.StatefulSets = statefulSets.Items
	}

	// Nodes are cluster-scoped, so they are collected even for a namespaced
	// run: half the reasons a namespaced pod is Pending live on the nodes.
	nodes, err := c.client.CoreV1().Nodes().List(ctx, listOpts)
	record("nodes", err)
	if nodes != nil {
		s.Nodes = nodes.Items
	}

	claims, err := c.client.CoreV1().PersistentVolumeClaims(ns).List(ctx, listOpts)
	record("persistentvolumeclaims", err)
	if claims != nil {
		s.PersistentVolumeClaims = claims.Items
	}

	services, err := c.client.CoreV1().Services(ns).List(ctx, listOpts)
	record("services", err)
	if services != nil {
		s.Services = services.Items
	}

	slices, err := c.client.DiscoveryV1().EndpointSlices(ns).List(ctx, listOpts)
	record("endpointslices", err)
	if slices != nil {
		s.EndpointSlices = slices.Items
	}

	quotas, err := c.client.CoreV1().ResourceQuotas(ns).List(ctx, listOpts)
	record("resourcequotas", err)
	if quotas != nil {
		s.ResourceQuotas = quotas.Items
	}

	Sanitize(s, c.options.KeepEnvValues)
	return s, errs
}

// explain turns the two API errors that people actually hit into sentences
// they can act on, and leaves everything else alone.
func explain(err error) error {
	switch {
	case apierrors.IsForbidden(err):
		return fmt.Errorf("%w (the current context lacks read access to this kind; "+
			"the snapshot will be incomplete and rules over this kind will stay silent)", err)
	case apierrors.IsNotFound(err):
		return fmt.Errorf("%w (the API is not served by this cluster version)", err)
	default:
		return err
	}
}

// DefaultTimeout bounds a collection. A cluster whose API server is itself the
// problem must not leave the CLI hanging with no output.
const DefaultTimeout = 30 * time.Second
