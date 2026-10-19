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
	for _, test := range []struct {
		name   string
		args   []string
		code   int
		stdout string
		stderr string
	}{
		{name: "version", args: []string{"version"}, code: 0, stdout: "memory dev\n"},
		{name: "no arguments", code: 2, stderr: "Usage: memory [--home DIR] [--json] <keys|spaces|policy|sync|check|recall|explain|changes|add|revise|assess|promote|version|conformance> [arguments]\n"},
		{name: "unknown command", args: []string{"unknown"}, code: 2, stderr: "memory: unknown command \"unknown\"\nUsage: memory [--home DIR] [--json] <keys|spaces|policy|sync|check|recall|explain|changes|add|revise|assess|promote|version|conformance> [arguments]\n"},
		{name: "extra argument", args: []string{"version", "extra"}, code: 2, stderr: "memory: version takes no arguments\nUsage: memory [--home DIR] [--json] <keys|spaces|policy|sync|check|recall|explain|changes|add|revise|assess|promote|version|conformance> [arguments]\n"},
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

// TestConformanceCLI proves the built command reports 66/66 semantic agreement and
// exits 0 from an unrelated cwd (embedded default and explicit source directory),
// while harness/usage errors exit 2
// without success output. Deployment vectors are explicitly excluded.
func TestConformanceCLI(t *testing.T) {
	semantic, err := filepath.Abs("../../../spec/kernel/vectors/semantic")
	if err != nil {
		t.Fatal(err)
	}
	deployment, err := filepath.Abs("../../../spec/kernel/vectors/deployment")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name      string
		args      []string
		code      int
		errorPart string
	}{
		{"default", []string{"conformance"}, 0, ""},
		{"explicit", []string{"conformance", semantic}, 0, ""},
		{"missing directory", []string{"conformance", filepath.Join(t.TempDir(), "missing")}, 2, "harness:"},
		{"empty directory", []string{"conformance", t.TempDir()}, 2, "no semantic vectors"},
		{"deployment", []string{"conformance", deployment}, 2, "deployment vectors are out of scope"},
		{"extra arguments", []string{"conformance", "a", "b"}, 2, "at most one"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command(binary, tc.args...)
			cmd.Dir = t.TempDir()
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
			if tc.code == 0 {
				lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
				if len(lines) < 76 || lines[66] != "66/66 semantic vectors pass" || lines[67] != "admission ops matched: 73/73 (admit 45/45, admit_raw 2/2, revise 26/26)" || lines[len(lines)-1] != "8 deployment vectors are out of scope." || stderr.Len() != 0 {
					t.Fatal(stdout.String(), stderr.String())
				}
				ids := map[string]bool{}
				passed := 0
				for _, line := range lines[:66] {
					fields := strings.Fields(line)
					if len(fields) < 2 || (fields[0] != "PASS" && fields[0] != "FAIL") || ids[fields[1]] {
						t.Fatal(line)
					}
					ids[fields[1]] = true
					if fields[0] == "PASS" {
						passed++
					} else if !strings.Contains(line, ": ") {
						t.Fatal(line)
					}
				}
				if passed != 66 {
					t.Fatal("passing whole-vector count", passed)
				}

			} else if stdout.Len() != 0 || !strings.Contains(stderr.String(), tc.errorPart) {
				t.Fatal(stdout.String(), stderr.String())
			}
		})
	}
}
