package main

import (
	"fmt"
	"io"
	"os"
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
	fmt.Fprintln(w, "Usage: memory version")
}
