// Command kollektor collects Kubernetes cluster state into a single evidence
// archive and replays it onto another cluster.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path"
	"slices"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/chxmxii/kollektor/internal/archive"
	"github.com/chxmxii/kollektor/internal/collect"
	"github.com/chxmxii/kollektor/internal/replay"
)

// version is set at build time via -ldflags "-X main.version=...".
var version = "dev"

const usage = `kollektor - collect Kubernetes cluster state for forensics, and replay it.

Usage:
  kollektor collect [flags]            collect into a .tar.zst archive
  kollektor inspect [flags] ARCHIVE    verify hashes and summarize an archive
  kollektor extract ARCHIVE [DIR]      verify, then unpack an archive
  kollektor replay  [flags] ARCHIVE    recreate the collected setup on a cluster
  kollektor version

Run "kollektor <command> -h" for command flags.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	switch cmd, args := os.Args[1], os.Args[2:]; cmd {
	case "collect":
		err = runCollect(ctx, args)
	case "inspect":
		err = runInspect(args)
	case "extract":
		err = runExtract(args)
	case "replay":
		err = runReplay(ctx, args)
	case "version", "--version":
		fmt.Println(version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
	if errors.Is(err, flag.ErrHelp) {
		return
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func newLogger(verbose bool) *slog.Logger {
	lvl := slog.LevelInfo
	if verbose {
		lvl = slog.LevelDebug
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
}

func runCollect(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("collect", flag.ContinueOnError)
	var o collect.Options
	var namespaces string
	var verbose bool
	fs.StringVar(&o.Output, "o", "", "output archive (default kollektor-<context>-<timestamp>.tar.zst)")
	fs.StringVar(&o.Kubeconfig, "kubeconfig", "", "path to kubeconfig")
	fs.StringVar(&o.Context, "context", "", "kubeconfig context to collect from")
	fs.StringVar(&namespaces, "namespaces", "", "comma-separated namespaces to collect (default all; cluster-scoped objects are always collected)")
	fs.BoolVar(&o.IncludeSecrets, "include-secrets", false, "store raw Secret values (default: replace values with SHA-256 hashes)")
	fs.BoolVar(&o.Logs, "logs", true, "collect container logs")
	fs.DurationVar(&o.LogSince, "log-since", 0, "only collect logs newer than this (e.g. 24h; default full log)")
	fs.IntVar(&o.Concurrency, "concurrency", 8, "parallel API requests")
	fs.BoolVar(&verbose, "v", false, "verbose logging")
	if err := fs.Parse(args); err != nil {
		return err
	}
	o.Namespaces = splitList(namespaces)
	o.ToolVersion = version

	out, m, err := collect.Run(ctx, o, newLogger(verbose))
	if err != nil {
		return err
	}
	var size int64
	for _, f := range m.Files {
		size += f.Size
	}
	fmt.Fprintf(os.Stderr, "\nwrote %s: %d files, %s uncompressed, %d collection errors (see manifest.json)\n",
		out, len(m.Files), humanBytes(size), len(m.Errors))
	return nil
}

func runInspect(args []string) error {
	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	list := fs.Bool("list", false, "list every file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: kollektor inspect [-list] ARCHIVE")
	}
	res, err := archive.Verify(fs.Arg(0))
	if err != nil {
		return err
	}
	m := res.Manifest
	md := m.Metadata
	fmt.Printf("format:      %s\n", m.Format)
	fmt.Printf("collected:   %s → %s (%s)\n", md.Started.Format(time.RFC3339), md.Finished.Format(time.RFC3339), md.Finished.Sub(md.Started).Round(time.Second))
	fmt.Printf("by:          %s@%s as %q (tool %s)\n", md.OSUser, md.Host, md.KubeUser, md.ToolVersion)
	fmt.Printf("cluster:     %s (%s, %s)\n", md.KubeContext, md.KubeServer, md.ServerVersion)
	ns := "all"
	if len(md.Namespaces) > 0 {
		ns = strings.Join(md.Namespaces, ",")
	}
	secrets := "redacted (SHA-256)"
	if md.SecretsRaw {
		secrets = "RAW VALUES"
	}
	fmt.Printf("namespaces:  %s\nsecrets:     %s\n\n", ns, secrets)

	sections := map[string]int{}
	var resources = map[string]int{}
	for _, f := range m.Files {
		top, rest, _ := strings.Cut(f.Path, "/")
		sections[top]++
		if top == "cluster" {
			if parts := strings.Split(rest, "/"); len(parts) == 3 {
				resources[parts[1]]++
			}
		}
	}
	fmt.Println("contents:")
	for _, k := range sortedKeys(sections) {
		fmt.Printf("  %-10s %d files\n", k+"/", sections[k])
	}
	fmt.Println("\nobjects by resource:")
	for _, k := range sortedKeys(resources) {
		fmt.Printf("  %6d  %s\n", resources[k], k)
	}

	if len(m.Errors) > 0 {
		fmt.Printf("\ncollection errors (%d):\n", len(m.Errors))
		for _, e := range m.Errors {
			fmt.Println("  -", e)
		}
	}
	if *list {
		fmt.Println("\nfiles:")
		for _, f := range m.Files {
			fmt.Printf("  %s  %10d  %s\n", f.SHA256, f.Size, f.Path)
		}
	}

	if len(res.Problems) > 0 {
		fmt.Printf("\nINTEGRITY CHECK FAILED (%d problems):\n", len(res.Problems))
		for _, p := range res.Problems {
			fmt.Println("  -", p)
		}
		return errors.New("archive does not match its manifest")
	}
	fmt.Printf("\nintegrity:   OK (%d files verified against manifest)\n", res.Verified)
	return nil
}

func runExtract(args []string) error {
	if len(args) < 1 || len(args) > 2 {
		return errors.New("usage: kollektor extract ARCHIVE [DIR]")
	}
	dir := "."
	if len(args) == 2 {
		dir = args[1]
	}
	res, err := archive.Verify(args[0])
	if err != nil {
		return err
	}
	if len(res.Problems) > 0 {
		return fmt.Errorf("refusing to extract: archive does not match its manifest (%d problems, run inspect)", len(res.Problems))
	}
	n, err := archive.Extract(args[0], dir)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "verified and extracted %d files to %s\n", n, dir)
	return nil
}

func runReplay(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("replay", flag.ContinueOnError)
	var o replay.Options
	var verbose bool
	fs.StringVar(&o.Kubeconfig, "kubeconfig", "", "path to kubeconfig of the target cluster")
	fs.StringVar(&o.Context, "context", "", "kubeconfig context of the target cluster")
	fs.StringVar(&o.Kind, "kind", "", "create a kind cluster with this name and replay into it")
	fs.StringVar(&o.OutDir, "out", "", "write ordered manifests to this directory instead of applying")
	fs.BoolVar(&o.DryRun, "dry-run", false, "server-side dry run")
	fs.BoolVar(&o.Plan.IncludeSystem, "include-system", false, "also replay system namespaces and built-in RBAC")
	fs.BoolVar(&o.Plan.IncludeWebhooks, "include-webhooks", false, "also replay admission webhooks and policies")
	fs.BoolVar(&verbose, "v", false, "verbose logging")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: kollektor replay [flags] ARCHIVE")
	}
	o.Archive = fs.Arg(0)

	res, err := replay.Run(ctx, o, newLogger(verbose))
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "\nplan: %d objects to replay\n", len(res.Plan.Objects))
	for _, reason := range sortedKeys(res.Plan.Skipped) {
		fmt.Fprintf(os.Stderr, "  skipped %4d  %s\n", res.Plan.Skipped[reason], reason)
	}
	if res.Plan.Redacted > 0 {
		fmt.Fprintf(os.Stderr, "  note: %d secrets were redacted at collection and are replayed with empty values\n", res.Plan.Redacted)
	}
	if o.OutDir != "" {
		fmt.Fprintf(os.Stderr, "\nwrote manifests to %s; apply them in order with: kubectl apply -f %s\n", o.OutDir, path.Join(o.OutDir, "<file>"))
		return nil
	}
	fmt.Fprintf(os.Stderr, "\napplied %d/%d objects to %s\n", res.Applied, len(res.Plan.Objects), res.Context)
	if len(res.Failed) > 0 {
		fmt.Fprintf(os.Stderr, "failed (%d):\n", len(res.Failed))
		for _, f := range res.Failed {
			fmt.Fprintln(os.Stderr, "  -", f)
		}
		return fmt.Errorf("%d objects failed to apply", len(res.Failed))
	}
	return nil
}

func splitList(s string) []string {
	var out []string
	for p := range strings.SplitSeq(s, ",") {
		if p = strings.TrimSpace(p); p != "" && !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
