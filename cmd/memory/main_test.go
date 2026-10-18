package main

import (
	"bytes"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestCLI proves the built CLI exits 0 for version and 2 with stderr-only usage for missing, unknown or extra arguments.
func TestCLI(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "memory")
	if output, err := exec.Command("go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatalf("build CLI: %v\n%s", err, output)
	}
	for _, test := range []struct {
		name   string
		args   []string
		code   int
		stdout string
		stderr string
	}{
		{name: "version", args: []string{"version"}, code: 0, stdout: "memory dev\n"},
		{name: "no arguments", code: 2, stderr: "Usage: memory version\n"},
		{name: "unknown command", args: []string{"unknown"}, code: 2, stderr: "memory: unknown command \"unknown\"\nUsage: memory version\n"},
		{name: "extra argument", args: []string{"version", "extra"}, code: 2, stderr: "memory: version takes no arguments\nUsage: memory version\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			cmd := exec.Command(binary, test.args...)
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			if err := cmd.Run(); err != nil {
				if _, ok := err.(*exec.ExitError); !ok {
					t.Fatalf("execute CLI: %v", err)
				}
			}
			if code := cmd.ProcessState.ExitCode(); code != test.code {
				t.Errorf("exit code = %d; want %d", code, test.code)
			}
			if stdout.String() != test.stdout || stderr.String() != test.stderr {
				t.Errorf("stdout = %q, stderr = %q; want %q, %q", stdout.String(), stderr.String(), test.stdout, test.stderr)
			}
		})
	}
}
