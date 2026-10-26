package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/relux-works/swarma-memory/go/agentprofile"
	"github.com/relux-works/swarma-memory/go/kernel"
)

// The only emission seam is a compiler overlay of the single build-time constant.
// No shipped flag, environment variable or home configuration can enable it.
func enabledAttributionBuild(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	source, e := filepath.Abs("features.go")
	if e != nil {
		t.Fatal(e)
	}
	replacement := filepath.Join(dir, "features.go")
	if e = os.WriteFile(replacement, []byte("package main\nconst attributedReviseEnabled = true\n"), 0600); e != nil {
		t.Fatal(e)
	}
	overlay := filepath.Join(dir, "overlay.json")
	b, _ := json.Marshal(map[string]any{"Replace": map[string]string{source: replacement}})
	if e = os.WriteFile(overlay, b, 0600); e != nil {
		t.Fatal(e)
	}
	binary := filepath.Join(dir, "memory")
	cmd := exec.Command("go", "build", "-overlay", overlay, "-o", binary, ".")
	if b, e := cmd.CombinedOutput(); e != nil {
		t.Fatal(e, string(b))
	}
	return binary
}
func attributionInvoke(h *cliHarness, binary, home, input string, want int, args ...string) map[string]any {
	h.t.Helper()
	cmd := exec.Command(binary, append([]string{"--home", home, "--json"}, args...)...)
	cmd.Env = h.env
	cmd.Dir = h.root
	cmd.Stdin = strings.NewReader(input)
	var out, stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	e := cmd.Run()
	if e != nil {
		if _, ok := e.(*exec.ExitError); !ok {
			h.t.Fatal(e)
		}
	}
	if cmd.ProcessState.ExitCode() != want {
		h.t.Fatalf("exit %d want %d: %s %s", cmd.ProcessState.ExitCode(), want, out.String(), stderr.String())
	}
	v, r := kernel.DecodeJSON(out.Bytes())
	if r != nil {
		h.t.Fatal("invalid output", out.String())
	}
	m := agentprofile.Object(v)
	if len(m) != 5 || m["data_classification"] != "data" {
		h.t.Fatal(m)
	}
	return m
}
func attributionStored(h *cliHarness, kind, id string, version int64) map[string]any {
	h.t.Helper()
	s, _ := selectSpace(h.config(h.owner), "space:test")
	b := h.git(s.ClonePath, "show", "HEAD:records/"+kind+"/"+hex.EncodeToString([]byte(id))+"/"+strconv64(version)+".json")
	v, r := kernel.DecodeJSON([]byte(b))
	if r != nil {
		h.t.Fatal(r)
	}
	return agentprofile.Object(agentprofile.Object(v)["record"])
}

// The binary agrees with the skill's rollout promise. In the reader-first phase,
// source flags refuse before input or Git mutation; phase 2 needs only the
// constant and skill update. Ordinary revisions and relation refusals persist.
func TestAttributedReviseShippedGate(t *testing.T) {
	skill, err := os.ReadFile("../../../SKILL.md")
	if err != nil {
		t.Fatal(err)
	}
	readerFirst := strings.Contains(string(skill), "Attributed revise arrives in the next release;")
	if attributedReviseEnabled == readerFirst {
		t.Fatal("shipped attribution gate disagrees with skill rollout promise")
	}
	h := newCLI(t)
	h.add(h.owner, "record:gated", "old content")
	before := h.writeState(h.owner)
	if !attributedReviseEnabled {
		for _, flags := range [][]string{{"--source-session", "R:S:M", "--source-text", "missing-file"}, {"--sources", "missing-file"}, {"--source-text", "missing-file"}} {
			args := append([]string{"revise", "record:gated", "--relation", "replace", "--expected-version", "1", "--content", "new content", "--idempotency-key", "gated-1"}, flags...)
			m, _ := h.invoke(h.owner, 2, args...)
			if errorCodeOf(m) != "feature_not_enabled" || m["data"] != nil {
				t.Fatal(m)
			}
			h.unchanged(h.owner, before)
		}
	}
	for _, relation := range []string{"withdraw", "challenge"} {
		m, _ := h.invoke(h.owner, 2, "revise", "record:gated", "--relation", relation, "--expected-version", "1", "--idempotency-key", "gated-1", "--sources", "missing-file")
		if errorCodeOf(m) != "usage" {
			t.Fatal(m)
		}
		h.unchanged(h.owner, before)
	}
	h.invoke(h.owner, 0, "revise", "record:gated", "--relation", "replace", "--expected-version", "1", "--content", "ordinary revision", "--idempotency-key", "plain-1")
}

// Each enabled build creates a single signed admission per revision and a fresh
// version-scoped basis. The default-off reader verifies both old and new wire,
// recalls the latest exact excerpt, and can still explain all three versions.
func TestAttributedReviseChain(t *testing.T) {
	enabled := enabledAttributionBuild(t)
	for _, relation := range []string{"replace", "correct"} {
		t.Run(relation, func(t *testing.T) {
			h := newCLI(t)
			id := "record:chain"
			h.input(h.owner, "version one excerpt", 0, "add", "assertion", "--id", id, "--content", "version one", "--idempotency-key", "chain-1", "--source-session", "R:S:M", "--source-text", "-")
			h.connectReader()
			h.invoke(h.reader, 0, "check")
			var first map[string]any
			var firstArgs []string
			for version := int64(2); version <= 3; version++ {
				text := "version " + strconv64(version) + " excerpt\n"
				args := []string{"revise", id, "--relation", relation, "--expected-version", strconv64(version - 1), "--content", "version " + strconv64(version), "--idempotency-key", "chain-" + strconv64(version), "--source-session", "R:S:M", "--source-text", "-"}
				// Exercise the cursor-pinned token path as well as the original numeric witness.
				if version == 3 {
					args[4] = "--expected-token"
					args[5] = h.readToken(h.owner, "explain", id, 2)
				}
				before := h.git(h.remote, "rev-parse", "main")
				m := attributionInvoke(h, enabled, h.owner, text, 0, args...)
				data := agentprofile.Object(m["data"])
				if data["id"] != id || data["version"] != version || len(agentprofile.Array(agentprofile.Object(data["receipt"])["refs"])) != 4 || h.git(h.remote, "rev-list", "--count", before+"..main") != "1" {
					t.Fatal("not one complete admission", m)
				}
				replay := attributionInvoke(h, enabled, h.owner, text, 0, args...)
				if !reflect.DeepEqual(data, agentprofile.Object(replay["data"])) {
					t.Fatal("replay changed result", m, replay)
				}
				if version == 2 {
					first, firstArgs = data, args
				}
				stem := id + ":v" + strconv64(version)
				source := attributionStored(h, "source", stem+":source", 1)
				if agentprofile.Object(source["body"])["excerpt"] != text {
					t.Fatal("excerpt changed", source)
				}
				basis := attributionStored(h, "justification", stem+":basis", 1)
				if !reflect.DeepEqual(agentprofile.Object(basis["body"])["premises"], []any{map[string]any{"kind": "source", "source": agentprofile.Ref(stem+":source", 1)}}) {
					t.Fatal("basis inherited old premises", basis)
				}
				check, _ := h.invoke(h.reader, 0, "check")
				for _, space := range agentprofile.Array(agentprofile.Object(check["data"])["spaces"]) {
					if len(agentprofile.Array(agentprofile.Object(space)["diagnostics"])) != 0 {
						t.Fatal("new reader diagnostics", check)
					}
				}
				recall, _ := h.invoke(h.reader, 0, "recall", "version "+strconv64(version))
				found := false
				for _, space := range agentprofile.Array(agentprofile.Object(recall["data"])["spaces"]) {
					for _, raw := range agentprofile.Array(agentprofile.Object(space)["views"]) {
						view := agentprofile.Object(raw)
						for _, rawItem := range agentprofile.Array(view["items"]) {
							item := agentprofile.Object(rawItem)
							if reflect.DeepEqual(item["ref"], agentprofile.Ref(id, version)) {
								found = true
								if item["currentness"] != "current" || !reflect.DeepEqual(item["source_refs"], []any{agentprofile.Ref(stem+":source", 1)}) {
									t.Fatal(item)
								}
							}
						}
						for _, rawSource := range agentprofile.Array(view["sources"]) {
							s := agentprofile.Object(rawSource)
							if !reflect.DeepEqual(s["ref"], agentprofile.Ref(stem+":source", 1)) || agentprofile.Object(s["excerpt"])["text"] != text {
								t.Fatal("wrong recalled source", s)
							}
						}
					}
				}
				if !found {
					t.Fatal("latest replacement absent", recall)
				}
			}
			replay := attributionInvoke(h, enabled, h.owner, "version 2 excerpt\n", 0, firstArgs...)
			d := agentprofile.Object(replay["data"])
			if !reflect.DeepEqual(first["receipt"], d["receipt"]) || first["commit"] != d["commit"] {
				t.Fatal("replay after v3 changed receipt", replay)
			}
			for v := int64(1); v <= 3; v++ {
				m, _ := h.invoke(h.reader, 0, "explain", id, "--version", strconv64(v))
				found := false
				for _, space := range agentprofile.Array(agentprofile.Object(m["data"])["spaces"]) {
					if len(agentprofile.Array(agentprofile.Object(space)["diagnostics"])) != 0 {
						t.Fatal(m)
					}
					for _, view := range agentprofile.Array(agentprofile.Object(space)["views"]) {
						for _, item := range agentprofile.Array(agentprofile.Object(view)["items"]) {
							if reflect.DeepEqual(agentprofile.Object(item)["ref"], agentprofile.Ref(id, v)) {
								found = true
								want := "historical"
								if v == 3 {
									want = "current"
								}
								if agentprofile.Object(item)["currentness"] != want {
									t.Fatal(item)
								}
							}
						}
					}
				}
				if !found {
					t.Fatal("version not verified/disclosed", m)
				}
			}
			h.invoke(h.reader, 0, "recall", "version 3")
		})
	}
}

// Input, CAS, relation, scanner and reserved auxiliary-ID failures preserve the
// complete published state. Nearby valid attribution and challenge controls pass.
func TestAttributedReviseRefusals(t *testing.T) {
	enabled := enabledAttributionBuild(t)
	h := newCLI(t)
	h.add(h.owner, "record:claim", "old claim")
	excerpt := filepath.Join(h.root, "excerpt.txt")
	if e := os.WriteFile(excerpt, []byte("safe excerpt"), 0600); e != nil {
		t.Fatal(e)
	}
	base := []string{"revise", "record:claim", "--relation", "replace", "--content", "new claim", "--expected-version", "1", "--idempotency-key", "claim-2"}
	for _, tc := range []struct {
		name, input, code string
		flags             []string
		exit              int
	}{
		{"missing text", "", "usage", []string{"--source-session", "R:S:M"}, 2},
		{"missing session", "", "usage", []string{"--source-text", excerpt}, 2},
		{"bad locator", "", "usage", []string{"--source-session", "R:S", "--source-text", excerpt}, 2},
		{"two stdin", "{}", "usage", []string{"--body", "-", "--sources", "-"}, 2},
		{"body and excerpt stdin", "{}", "usage", []string{"--body", "-", "--source-session", "R:S:M", "--source-text", "-"}, 2},
		{"scanner excerpt", "-----BEGIN PRIVATE KEY-----", "scan_refused", []string{"--source-session", "R:S:M", "--source-text", "-"}, 3},
		{"missing source ref", `[{"id":"source:missing","version":1}]`, "invalid_reference", []string{"--sources", "-"}, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := h.writeState(h.owner)
			args := append(append([]string{}, base...), tc.flags...)
			if strings.HasPrefix(tc.name, "two stdin") || tc.name == "body and excerpt stdin" {
				args = append(args[:4], args[6:]...)
			}
			m := attributionInvoke(h, enabled, h.owner, tc.input, tc.exit, args...)
			if errorCodeOf(m) != tc.code {
				t.Fatal(m)
			}
			if tc.code == "scan_refused" && len(agentprofile.Array(agentprofile.Object(m["data"])["findings"])) == 0 {
				t.Fatal("no quarantine findings", m)
			}
			h.unchanged(h.owner, before)
		})
	}
	m := attributionInvoke(h, enabled, h.owner, "safe excerpt", 0, append(base, "--source-session", "R:S:M", "--source-text", "-")...)
	if agentprofile.Object(m["data"])["version"] != int64(2) {
		t.Fatal(m)
	}
	before := h.writeState(h.owner)
	stale := append([]string{}, base...)
	stale[9] = "stale-1"
	m = attributionInvoke(h, enabled, h.owner, "safe excerpt", 3, append(stale, "--source-session", "R:S:M", "--source-text", "-")...)
	if errorCodeOf(m) != "version_conflict" {
		t.Fatal(m)
	}
	h.unchanged(h.owner, before)
	for _, relation := range []string{"withdraw", "challenge"} {
		for _, flags := range [][]string{{"--sources", excerpt}, {"--source-session", "R:S:M", "--source-text", excerpt}} {
			m = attributionInvoke(h, enabled, h.owner, "", 2, append([]string{"revise", "record:claim", "--relation", relation, "--expected-version", "2", "--idempotency-key", "refuse-1"}, flags...)...)
			if errorCodeOf(m) != "usage" {
				t.Fatal(m)
			}
			h.unchanged(h.owner, before)
		}
	}
	h.invoke(h.owner, 0, "revise", "record:claim", "--relation", "challenge", "--expected-version", "2", "--idempotency-key", "challenge-1")
	sourceBody := sourceBody("agent:owner", "document:collision", "edition:one")
	h.input(h.owner, string(jsonBytesForTest(t, sourceBody)), 0, "add", "source", "--id", "record:claim:v3:source", "--idempotency-key", "collision-1", "--body", "-")
	before = h.writeState(h.owner)
	m = attributionInvoke(h, enabled, h.owner, "safe excerpt", 3, "revise", "record:claim", "--relation", "replace", "--expected-version", "2", "--content", "collision", "--idempotency-key", "collision-2", "--source-session", "R:S:M", "--source-text", "-")
	if errorCodeOf(m) != "invalid_shape" {
		t.Fatal(m)
	}
	h.unchanged(h.owner, before)
	bodyFile := filepath.Join(h.root, "source-body.json")
	if e := os.WriteFile(bodyFile, jsonBytesForTest(t, sourceBody), 0600); e != nil {
		t.Fatal(e)
	}
	m = attributionInvoke(h, enabled, h.owner, "safe excerpt", 2, "revise", "record:claim:v3:source", "--relation", "replace", "--expected-version", "1", "--body", bodyFile, "--idempotency-key", "source-revise-1", "--source-session", "R:S:M", "--source-text", "-")
	if errorCodeOf(m) != "usage" {
		t.Fatal(m)
	}
	h.unchanged(h.owner, before)
}

// Existing source refs can form a one-auxiliary basis without a new session;
// restoration keeps the withdrawal's explicit expected-id CAS semantics.
func TestAttributedReviseExistingSourcesAndRestore(t *testing.T) {
	enabled := enabledAttributionBuild(t)
	h := newCLI(t)
	id := "record:restore"
	h.input(h.owner, "old source", 0, "add", "assertion", "--id", id, "--content", "old", "--idempotency-key", "restore-1", "--source-session", "R:S:M", "--source-text", "-")
	refs := filepath.Join(h.root, "sources.json")
	if e := os.WriteFile(refs, []byte(`[{"id":"record:restore:source","version":1}]`), 0600); e != nil {
		t.Fatal(e)
	}
	m := attributionInvoke(h, enabled, h.owner, "", 0, "revise", id, "--relation", "correct", "--expected-version", "1", "--idempotency-key", "restore-2", "--content", "corrected", "--sources", refs)
	if len(agentprofile.Array(agentprofile.Object(agentprofile.Object(m["data"])["receipt"])["refs"])) != 3 {
		t.Fatal("expected replacement, revision and basis", m)
	}
	basis := attributionStored(h, "justification", id+":v2:basis", 1)
	if !reflect.DeepEqual(agentprofile.Object(basis["body"])["premises"], []any{map[string]any{"kind": "source", "source": agentprofile.Ref(id+":source", 1)}}) {
		t.Fatal(basis)
	}
	h.invoke(h.owner, 0, "revise", id, "--relation", "withdraw", "--expected-version", "2", "--id", "revision:withdraw", "--idempotency-key", "withdraw-1")
	m = attributionInvoke(h, enabled, h.owner, "restored source", 0, "revise", id, "--relation", "correct", "--expected-id", "revision:withdraw", "--expected-version", "1", "--idempotency-key", "restore-3", "--content", "restored", "--source-session", "R:S:M", "--source-text", "-")
	if agentprofile.Object(m["data"])["version"] != int64(3) {
		t.Fatal(m)
	}
	h.connectReader()
	check, raw := h.invoke(h.reader, 0, "check")
	if strings.Contains(raw, `"diagnostics":[{`) {
		t.Fatal(check)
	}
	h.invoke(h.reader, 0, "recall", "restored")
}
