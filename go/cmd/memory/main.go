package main

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"sort"

	assets "github.com/relux-works/swarma-memory/go/assets"
	"github.com/relux-works/swarma-memory/go/conformance"
	"github.com/relux-works/swarma-memory/go/kernel"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	for _, arg := range args {
		if arg == "--json" || arg == "--home" {
			return runCLI(args, stdout, stderr)
		}
	}
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	if args[0] == "conformance" {
		return runConformance(args[1:], stdout, stderr)
	}
	if args[0] != "version" {
		switch args[0] {
		case "keys", "spaces", "directory", "policy", "sync", "check", "recall", "explain", "changes", "add", "revise", "assess", "promote":
			return runCLI(args, stdout, stderr)
		}
		fmt.Fprintf(stderr, "memory: unknown command %q\n", args[0])
		usage(stderr)
		return 2
	}
	if len(args) != 1 {
		fmt.Fprintln(stderr, "memory: version takes no arguments")
		usage(stderr)
		return 2
	}
	fmt.Fprintln(stdout, currentVersion())
	return 0
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "Usage: memory [--home DIR] [--json] <keys|spaces|directory|policy|sync|check|recall|explain|changes|add|revise|assess|promote|version|conformance> [arguments]")
}

// Default conformance uses the embedded public suite, independent of cwd.
func runConformance(args []string, stdout, stderr io.Writer) int {
	if len(args) > 1 {
		fmt.Fprintln(stderr, "memory: conformance takes at most one vectors directory")
		return 2
	}
	vectorFS, err := fs.Sub(assets.Files, "spec/kernel/vectors/semantic")
	if err != nil {
		fmt.Fprintln(stderr, "memory: harness: embedded vectors unavailable")
		return 2
	}
	if len(args) == 1 {
		vectorFS = os.DirFS(args[0])
	}
	schemaFS, err := fs.Sub(assets.Files, "spec/kernel/schemas")
	if err != nil {
		fmt.Fprintln(stderr, "memory: harness: embedded schemas unavailable")
		return 2
	}
	schemas, r := kernel.LoadSchemas(schemaFS)
	if r != nil {
		fmt.Fprintf(stderr, "memory: harness: schemas: %s\n", r.Code)
		return 2
	}
	vectors, err := conformance.Load(vectorFS, schemas)
	if err != nil {
		fmt.Fprintln(stderr, "memory:", err)
		return 2
	}
	verdicts, err := conformance.Run(vectors, conformance.KernelExecutor{Schemas: schemas})
	if err != nil {
		fmt.Fprintln(stderr, "memory:", err)
		return 2
	}
	for _, ratchet := range []struct {
		path  string
		check func([]conformance.Verdict, string) ([]string, error)
	}{{"conformance/passing.txt", conformance.CheckRatchet}, {"conformance/passing-ops.txt", conformance.CheckOperationRatchet}} {
		data, err := assets.Files.ReadFile(ratchet.path)
		if err != nil {
			fmt.Fprintln(stderr, "memory: ratchet:", err)
			return 2
		}
		added, err := ratchet.check(verdicts, string(data))
		if err != nil {
			fmt.Fprintln(stderr, "memory:", err)
			return 1
		}
		for _, id := range added {
			fmt.Fprintln(stdout, "newly matching:", id)
		}
	}
	passed := 0
	for _, v := range verdicts {
		if v.Pass {
			passed++
			fmt.Fprintln(stdout, "PASS", v.ID)
		} else {
			fmt.Fprintf(stdout, "FAIL %s: %s\n", v.ID, v.Reason)
		}
	}
	fmt.Fprintf(stdout, "%d/%d semantic vectors pass\n", passed, len(verdicts))
	counts := conformance.CountParts(verdicts)
	total, matched := 0, 0
	for _, kind := range []string{"admit", "admit_raw", "revise"} {
		total += counts[kind].Total
		matched += counts[kind].Matched
	}
	fmt.Fprintf(stdout, "admission ops matched: %d/%d (admit %d/%d, admit_raw %d/%d, revise %d/%d)\n", matched, total, counts["admit"].Matched, counts["admit"].Total, counts["admit_raw"].Matched, counts["admit_raw"].Total, counts["revise"].Matched, counts["revise"].Total)
	fmt.Fprintf(stdout, "load ops matched: %d/%d\n", counts["load"].Matched, counts["load"].Total)
	other := map[string]bool{}
	for _, v := range verdicts {
		for _, p := range v.Parts {
			if p.Kind != "inventory" && p.Kind != "admit" && p.Kind != "admit_raw" && p.Kind != "revise" && p.Kind != "load" {
				other[p.Kind] = true
			}
		}
	}
	names := []string{}
	for name := range other {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		c := counts[name]
		fmt.Fprintf(stdout, "%s ops matched: %d/%d\n", name, c.Matched, c.Total)
	}
	for _, name := range []string{"record_refs", "erased_refs", "custody_present", "dirty", "control_observations", "external_effects"} {
		c := counts[name]
		fmt.Fprintf(stdout, "%s inventories matched: %d/%d\n", name, c.Matched, c.Total)
	}
	fmt.Fprintln(stdout, "8 deployment vectors are out of scope.")
	if passed != len(verdicts) {
		return 1
	}
	return 0
}
