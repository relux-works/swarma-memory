package main

import (
	"bytes"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestCLI proves missing, unknown or extra arguments exit 2 with stderr-only usage.
// Version metadata is covered separately by TestVersionCommand.
func TestCLI(t *testing.T) {
	for _, test := range []struct {
		name   string
		args   []string
		code   int
		stdout string
		stderr string
	}{
		{name: "no arguments", code: 2, stderr: "Usage: memory [--home DIR] [--json] <keys|spaces|directory|policy|sync|check|recall|explain|changes|add|revise|assess|promote|version|conformance> [arguments]\n"},
		{name: "unknown command", args: []string{"unknown"}, code: 2, stderr: "memory: unknown command \"unknown\"\nUsage: memory [--home DIR] [--json] <keys|spaces|directory|policy|sync|check|recall|explain|changes|add|revise|assess|promote|version|conformance> [arguments]\n"},
		{name: "extra argument", args: []string{"version", "extra"}, code: 2, stderr: "memory: version takes no arguments\nUsage: memory [--home DIR] [--json] <keys|spaces|directory|policy|sync|check|recall|explain|changes|add|revise|assess|promote|version|conformance> [arguments]\n"},
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

// TestConformanceCLI proves the built command reports 78/78 semantic agreement and
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
				if len(lines) < 87 || lines[78] != "78/78 semantic vectors pass" || lines[79] != "admission ops matched: 83/83 (admit 48/48, admit_raw 3/3, revise 32/32)" || lines[len(lines)-1] != "8 deployment vectors are out of scope." || stderr.Len() != 0 {
					t.Fatal(stdout.String(), stderr.String())
				}
				ids := map[string]bool{}
				passed := 0
				for _, line := range lines[:78] {
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
				if passed != 78 {
					t.Fatal("passing whole-vector count", passed)
				}

			} else if stdout.Len() != 0 || !strings.Contains(stderr.String(), tc.errorPart) {
				t.Fatal(stdout.String(), stderr.String())
			}
		})
	}
}

// Compact output decodes locator/excerpt text, while JSON has exactly the
// original payload; an erased entry never acquires locator or excerpt details.
func TestSourceOutputModes(t *testing.T) {
	source := map[string]any{"ref": map[string]any{"id": "rec:s", "version": int64(1)}, "availability": "unavailable", "owner": "runtime:example", "object": "session:planning", "revision": "message:42", "digest": nil, "origin": "{\"runtime\":\"example\",\"session\":\"planning\",\"message\":\"42\"}", "excerpt": map[string]any{"state": "present", "text": "café\nsecond line\n"}}
	data := map[string]any{"spaces": []any{map[string]any{"views": []any{map[string]any{"sources": []any{source}}}}}}
	var compact, raw, stderr bytes.Buffer
	if emit(&compact, &stderr, false, "recall", data, nil) != 0 || emit(&raw, &stderr, true, "recall", data, nil) != 0 {
		t.Fatal("render failed")
	}
	if !strings.Contains(compact.String(), "runtime: example; session: planning; message: 42") || !strings.Contains(compact.String(), "café\nsecond line\n") || !strings.Contains(compact.String(), "unavailable") {
		t.Fatal("missing decoded details", compact.String())
	}
	var decoded struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(raw.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	want, _ := json.Marshal(data)
	got, _ := json.Marshal(decoded.Data)
	if !bytes.Equal(want, got) || strings.Count(raw.String(), "\n") != 1 {
		t.Fatal("JSON payload changed", raw.String())
	}
	erased := map[string]any{"ref": source["ref"], "availability": "erased", "excerpt": map[string]any{"state": "erased"}}
	data["spaces"].([]any)[0].(map[string]any)["views"].([]any)[0].(map[string]any)["sources"] = []any{erased}
	compact.Reset()
	renderSourceDetails(&compact, data)
	if strings.Contains(compact.String(), "runtime:") || strings.Contains(compact.String(), "excerpt") || !strings.Contains(compact.String(), "erased") {
		t.Fatal("erased details rendered", compact.String())
	}
}
