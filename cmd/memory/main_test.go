package main

import (
	"bytes"
	"os/exec"
	"path/filepath"
	"strings"
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
		{name: "no arguments", code: 2, stderr: "Usage: memory version | conformance [<vectors-dir>]\n"},
		{name: "unknown command", args: []string{"unknown"}, code: 2, stderr: "memory: unknown command \"unknown\"\nUsage: memory version | conformance [<vectors-dir>]\n"},
		{name: "extra argument", args: []string{"version", "extra"}, code: 2, stderr: "memory: version takes no arguments\nUsage: memory version | conformance [<vectors-dir>]\n"},
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

// TestConformanceCLI proves the built command reports all semantic failures and
// exits 1 (default and explicit directory), while harness/usage errors exit 2
// without success output. Deployment vectors are explicitly excluded.
func TestConformanceCLI(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "memory")
	if output, err := exec.Command("go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, output)
	}
	for _, tc := range []struct {
		name      string
		args      []string
		code      int
		errorPart string
	}{
		{"default", []string{"conformance"}, 1, ""},
		{"explicit", []string{"conformance", "spec/kernel/vectors/semantic"}, 1, ""},
		{"missing directory", []string{"conformance", filepath.Join(t.TempDir(), "missing")}, 2, "harness:"},
		{"empty directory", []string{"conformance", t.TempDir()}, 2, "no semantic vectors"},
		{"deployment", []string{"conformance", "spec/kernel/vectors/deployment"}, 2, "deployment vectors are out of scope"},
		{"extra arguments", []string{"conformance", "a", "b"}, 2, "at most one"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command(binary, tc.args...)
			cmd.Dir = "../.."
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			if err := cmd.Run(); err != nil {
				if _, ok := err.(*exec.ExitError); !ok {
					t.Fatal(err)
				}
			}
			if cmd.ProcessState.ExitCode() != tc.code {
				t.Fatal(cmd.ProcessState.ExitCode(), stderr.String())
			}
			if tc.code == 1 {
				lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
				if len(lines) < 76 || lines[66] != "0/66 semantic vectors pass" || lines[67] != "admission ops matched: 70/73 (admit 42/45, admit_raw 2/2, revise 26/26)" || lines[len(lines)-1] != "8 deployment vectors are out of scope." || stderr.Len() != 0 {
					t.Fatal(stdout.String(), stderr.String())
				}
				ids := map[string]bool{}
				for _, line := range lines[:66] {
					parts := strings.SplitN(line, ": ", 2)
					if len(parts) != 2 || !strings.HasPrefix(parts[0], "FAIL ") || parts[1] == "" || ids[parts[0]] {
						t.Fatal(line)
					}
					ids[parts[0]] = true
				}
			} else if stdout.Len() != 0 || !strings.Contains(stderr.String(), tc.errorPart) {
				t.Fatal(stdout.String(), stderr.String())
			}
		})
	}
}
