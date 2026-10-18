package main

import (
	"fmt"
	"io"
	"os"

	"github.com/relux-works/swarma-memory/conformance"
	"github.com/relux-works/swarma-memory/kernel"
)

const version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	if args[0] == "conformance" {
		return runConformance(args[1:], stdout, stderr)
	}
	if args[0] != "version" {
		fmt.Fprintf(stderr, "memory: unknown command %q\n", args[0])
		usage(stderr)
		return 2
	}
	if len(args) != 1 {
		fmt.Fprintln(stderr, "memory: version takes no arguments")
		usage(stderr)
		return 2
	}
	fmt.Fprintf(stdout, "memory %s\n", version)
	return 0
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "Usage: memory version | conformance [<vectors-dir>]")
}

// Run from the repository root, where the normative schema package is available.
func runConformance(args []string, stdout, stderr io.Writer) int {
	if len(args) > 1 {
		fmt.Fprintln(stderr, "memory: conformance takes at most one vectors directory")
		return 2
	}
	dir := "spec/kernel/vectors/semantic"
	if len(args) == 1 {
		dir = args[0]
	}
	schemas, r := kernel.LoadSchemas(os.DirFS("spec/kernel/schemas"))
	if r != nil {
		fmt.Fprintf(stderr, "memory: harness: schemas: %s\n", r.Code)
		return 2
	}
	vectors, err := conformance.Load(os.DirFS(dir), schemas)
	if err != nil {
		fmt.Fprintln(stderr, "memory:", err)
		return 2
	}
	verdicts, err := conformance.Run(vectors, conformance.KernelExecutor{})
	if err != nil {
		fmt.Fprintln(stderr, "memory:", err)
		return 2
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
	fmt.Fprintln(stdout, "8 deployment vectors are out of scope.")
	if passed != len(verdicts) {
		return 1
	}
	return 0
}
