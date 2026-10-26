package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/swarma-memory/go/agentprofile"
)

// The four POSIX blocks in the installed skill are executable examples, not
// copies maintained in this test. Both runtime locator variants retain the exact
// excerpt, disclose its ref, and revise the version observed by the preceding read.
// Invalid locators and missing/stale preconditions publish no partial writes.
func TestSkillWorkedExamples(t *testing.T) {
	skill, err := os.ReadFile(filepath.Join("..", "..", "..", "SKILL.md"))
	if err != nil {
		t.Fatal(err)
	}
	var blocks []string
	for _, part := range strings.Split(string(skill), "```sh\n")[1:] {
		block, _, found := strings.Cut(part, "\n```")
		if !found {
			t.Fatal("unterminated skill example")
		}
		blocks = append(blocks, block)
	}
	if len(blocks) != 4 {
		t.Fatalf("want source, revision read, revision write and exact dependency blocks; got %d", len(blocks))
	}
	for _, runtime := range []string{"codex", "claude-code"} {
		t.Run(runtime, func(t *testing.T) {
			h := newCLI(t)
			bin := filepath.Join(h.root, "bin")
			if err := os.Mkdir(bin, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(binary, filepath.Join(bin, "memory")); err != nil {
				t.Fatal(err)
			}
			env := append([]string{}, h.env...)
			for i, value := range env {
				if strings.HasPrefix(value, "PATH=") {
					env[i] = "PATH=" + bin + string(os.PathListSeparator) + strings.TrimPrefix(value, "PATH=")
				}
			}
			env = append(env, "MEMORY_HOME="+h.owner, "runtime="+runtime, "session=fixture-session", "message=12")
			run := func(script string, exit int, code string) []map[string]any {
				t.Helper()
				cmd := exec.Command("/bin/sh", "-eu", "-c", script)
				cmd.Env, cmd.Dir = env, h.root
				var out, stderr bytes.Buffer
				cmd.Stdout, cmd.Stderr = &out, &stderr
				if err := cmd.Run(); err != nil {
					if _, ok := err.(*exec.ExitError); !ok {
						t.Fatal(err)
					}
				}
				if cmd.ProcessState.ExitCode() != exit {
					t.Fatalf("example exit %d want %d: %s %s", cmd.ProcessState.ExitCode(), exit, out.String(), stderr.String())
				}
				decoder := json.NewDecoder(&out)
				var results []map[string]any
				for {
					var result map[string]any
					if err := decoder.Decode(&result); err != nil {
						if err == io.EOF {
							break
						}
						t.Fatal("example emitted invalid JSON", err)
					}
					if result["data_classification"] != "data" {
						t.Fatal("example lost data boundary", result)
					}
					results = append(results, result)
				}
				if len(results) == 0 {
					t.Fatal("example emitted no result")
				}
				for i, result := range results {
					if i == len(results)-1 && exit != 0 {
						if errorCodeOf(result) != code || stderr.Len() == 0 {
							t.Fatal("wrong refusal", result, stderr.String())
						}
					} else if result["error"] != nil {
						t.Fatal("example failed", result)
					}
				}
				if exit == 0 && stderr.Len() != 0 {
					t.Fatal(stderr.String())
				}
				return results
			}
			mutate := func(script, old, replacement string) string {
				t.Helper()
				if strings.Count(script, old) != 1 {
					t.Fatalf("negative control not applied exactly once: %q", old)
				}
				return strings.Replace(script, old, replacement, 1)
			}
			before := h.writeState(h.owner)
			run(mutate(blocks[0], `"$runtime:$session:$message"`, `"$runtime:$session"`), 2, "usage")
			h.unchanged(h.owner, before)
			run(blocks[0], 0, "")
			space, err := selectSpace(h.config(h.owner), "space:test")
			if err != nil {
				t.Fatal(err)
			}
			sourceID := "record:queue-choice:source"
			raw := h.git(space.ClonePath, "show", "HEAD:records/source/"+hex.EncodeToString([]byte(sourceID))+"/1.json")
			var stored map[string]any
			if err := json.Unmarshal([]byte(raw), &stored); err != nil {
				t.Fatal(err)
			}
			body := agentprofile.Object(agentprofile.Object(stored["record"])["body"])
			var locator map[string]any
			if err := json.Unmarshal([]byte(body["origin"].(string)), &locator); err != nil {
				t.Fatal(err)
			}
			if locator["runtime"] != runtime || locator["session"] != "fixture-session" || locator["message"] != "12" || body["excerpt"] != "Decision: use a bounded durable queue\n" {
				t.Fatal("example lost exact excerpt or locator", body)
			}
			reads := run(blocks[1], 0, "")
			var items []map[string]any
			for _, space := range agentprofile.Array(agentprofile.Object(reads[len(reads)-1]["data"])["spaces"]) {
				for _, view := range agentprofile.Array(agentprofile.Object(space)["views"]) {
					for _, item := range agentprofile.Array(agentprofile.Object(view)["items"]) {
						items = append(items, agentprofile.Object(item))
					}
				}
			}
			if len(items) != 1 {
				t.Fatalf("read must disclose exactly the example target, got %v", items)
			}
			ref := agentprofile.Object(items[0]["ref"])
			refs := agentprofile.Array(items[0]["source_refs"])
			if ref["id"] != "record:queue-choice" || ref["version"] != float64(1) || len(refs) != 1 || agentprofile.Object(refs[0])["id"] != sourceID || items[0]["write_token"] == nil {
				t.Fatal("read lacks the documented version/token/source ref", items[0])
			}
			encoded, err := json.Marshal(items[0])
			if err != nil || bytes.Contains(encoded, []byte(`"excerpt"`)) {
				t.Fatal("v1 read unexpectedly discloses excerpt", string(encoded), err)
			}
			before = h.writeState(h.owner)
			run(mutate(blocks[2], "--expected-version 1", ""), 2, "usage")
			h.unchanged(h.owner, before)
			run(mutate(blocks[2], "--expected-version 1", "--expected-version 2"), 3, "version_conflict")
			h.unchanged(h.owner, before)
			run(blocks[2], 0, "")
			revised := agentprofile.Object(h.stored(h.owner, "space:test", "record:queue-choice", 2)["body"])
			if agentprofile.Object(agentprofile.Array(revised["content"])[0])["value"] != "Decision: use a bounded durable queue with capacity 128" {
				t.Fatal("revision did not replace the observed content", revised)
			}
			before = h.writeState(h.owner)
			run(mutate(blocks[2], "queue-choice-2", "queue-choice-stale"), 3, "version_conflict")
			h.unchanged(h.owner, before)
			// The installed exact-dependency example accepts the revised record;
			// a missing dependency refuses rather than becoming an empty success.
			run(blocks[3], 0, "")
			run(mutate(blocks[3], "record:queue-choice", "record:missing"), 3, "record_not_found")
			h.unchanged(h.owner, before)
			h.invoke(h.owner, 0, "check")
		})
	}
}
