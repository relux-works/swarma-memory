package e2e_test

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type diagnostic struct {
	Commit string `json:"commit"`
	Path   string `json:"path"`
	Code   string `json:"code"`
}

type readSpace struct {
	ID          string            `json:"id"`
	Cursor      string            `json:"cursor"`
	Views       []json.RawMessage `json:"views"`
	Diagnostics []diagnostic      `json:"diagnostics"`
}

func readSpaces(t *testing.T, r reply) ([]readSpace, map[string]string) {
	t.Helper()
	data := object(t, r.Data, "cursor", "spaces")
	cursor := text(t, data["cursor"])
	if !strings.HasPrefix(cursor, "memory:1:") {
		t.Fatal("missing composite cursor")
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(strings.TrimPrefix(cursor, "memory:1:"))
	if err != nil {
		t.Fatal(err)
	}
	var cursors map[string]string
	if err := json.Unmarshal(raw, &cursors); err != nil {
		t.Fatal(err)
	}
	var rows []json.RawMessage
	if err := json.Unmarshal(data["spaces"], &rows); err != nil || rows == nil {
		t.Fatal("invalid space array", err)
	}
	out := []readSpace{}
	for _, row := range rows {
		fields := object(t, row, "id", "cursor", "views", "diagnostics")
		var s readSpace
		if err := json.Unmarshal(row, &s); err != nil || s.Views == nil || s.Diagnostics == nil {
			t.Fatal("invalid read space", err)
		}
		if len(s.Cursor) != 40 && len(s.Cursor) != 64 || cursors[s.ID] != s.Cursor {
			t.Fatal("space/composite cursor mismatch")
		}
		var diagnostics []json.RawMessage
		json.Unmarshal(fields["diagnostics"], &diagnostics)
		for _, d := range diagnostics {
			object(t, d, "commit", "path", "code")
		}
		out = append(out, s)
	}
	if len(out) != len(cursors) {
		t.Fatal("cursor contains extra/absent spaces")
	}
	return out, cursors
}

func clean(t *testing.T, a *agent, p project, head string) {
	t.Helper()
	a.run(0, "sync", "--space", p.id)
	r := a.run(0, "check", "--space", p.id)
	data := object(t, r.Data, "spaces")
	var spaces []json.RawMessage
	if err := json.Unmarshal(data["spaces"], &spaces); err != nil || len(spaces) != 1 {
		t.Fatal("missing check result", err)
	}
	s := object(t, spaces[0], "id", "policy", "policy_digest", "cursor", "diagnostic_count", "diagnostics")
	if text(t, s["id"]) != p.id || text(t, s["cursor"]) != head || string(s["diagnostic_count"]) != "0" || string(s["diagnostics"]) != "[]" {
		t.Fatal("space not clean/current")
	}
}

func forgeryDiagnostics(t *testing.T, got []diagnostic, want map[string]string, head string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatal("wrong forgery diagnostic count", got)
	}
	seen := map[string]bool{}
	for _, d := range got {
		if d.Commit != head || want[d.Path] != d.Code || seen[d.Path] {
			t.Fatal("unexpected/repeated forgery diagnostic", d)
		}
		seen[d.Path] = true
	}
}

// Scenario 1: a CLI owner grants two independently keyed agents; both clone the
// pinned project and pass sync/check. This phase does not exercise valid writes.
func TestPhaseAOwnerAndTwoAgents(t *testing.T) {
	f := newFixture(t)
	p := f.project("space:project", "project")
	head := f.owner.git(p.remote, "rev-parse", "main")
	if f.a.keyID == f.b.keyID || f.a.keyID == f.owner.keyID || f.b.keyID == f.owner.keyID {
		t.Fatal("agents share identity keys")
	}
	if clonePath(f.a, p) == clonePath(f.b, p) {
		t.Fatal("agents share clones")
	}
	for _, a := range []*agent{f.a, f.b} {
		clean(t, a, p, head)
		summary := object(t, a.run(0, "spaces", "show", p.id).Data, "id", "policy", "policy_digest", "cursor", "diagnostic_count", "diagnostics")
		var policy struct {
			Readers []struct{ Identity string }
			Writers []struct{ Identity string }
		}
		if err := json.Unmarshal(summary["policy"], &policy); err != nil {
			t.Fatal(err)
		}
		for _, granted := range []*agent{f.a, f.b} {
			reader, writer := false, false
			for _, r := range policy.Readers {
				reader = reader || r.Identity == granted.identity
			}
			for _, w := range policy.Writers {
				writer = writer || w.Identity == granted.identity
			}
			if !reader || !writer {
				t.Fatal("signed policy omitted a requested agent grant")
			}
		}
		for _, name := range []string{"config.json", "localkey.json"} {
			info, err := os.Stat(filepath.Join(a.home, name))
			if err != nil || info.Mode().Perm() != 0600 {
				t.Fatal("agent file permissions", name, err)
			}
		}
		spaces, _ := readSpaces(t, a.read("recall", 0))
		if len(spaces) != 1 || spaces[0].ID != p.id || len(spaces[0].Views) != 0 {
			t.Fatal("new space is not readable/empty")
		}
	}
}

// Scenario 2: a raw push's structurally valid records reach the signature/key
// checks, receive the exact diagnostics, and never enter either reader's view.
// Empty clean views are the positive control until legitimate CLI writes land.
func TestPhaseAForgedPushExcluded(t *testing.T) {
	f := newFixture(t)
	p := f.project("space:project", "project")
	head := f.owner.git(p.remote, "rev-parse", "main")
	for _, a := range []*agent{f.a, f.b} {
		clean(t, a, p, head)
		spaces, _ := readSpaces(t, a.read("recall", 0))
		if len(spaces) != 1 || len(spaces[0].Views) != 0 {
			t.Fatal("unexpected baseline records")
		}
	}
	rogue := f.newAgent("unregistered")
	clone := clonePath(f.a, p)
	f.a.git(clone, "switch", "--detach", head)
	want := map[string]string{}
	for _, plant := range []struct{ id, key, submitter, code string }{
		{"record:bad-signature", f.a.keyID, f.a.identity, "invalid_signature"},
		{"record:unknown-key", rogue.keyID, rogue.identity, "unregistered_key"},
	} {
		record := forgedRecord(p.id, plant.id, plant.submitter, plant.key)
		path := "records/assertion/" + hex.EncodeToString([]byte(plant.id)) + "/1.json"
		filename := filepath.Join(clone, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(filename), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filename, record, 0644); err != nil {
			t.Fatal(err)
		}
		want[path] = plant.code
	}
	f.a.git(clone, "add", "--", "records")
	f.a.git(clone, "commit", "-S", "-m", "adversarial record fixtures")
	badHead := f.a.git(clone, "rev-parse", "HEAD")
	f.a.git(clone, "push", "origin", "HEAD:refs/heads/main")
	f.verifyCommits(p)
	for _, a := range []*agent{f.a, f.b} {
		r := a.run(5, "check")
		refused(t, r, "verification_failed")
		check := object(t, r.Data, "spaces")
		var summaries []json.RawMessage
		if err := json.Unmarshal(check["spaces"], &summaries); err != nil || len(summaries) != 1 {
			t.Fatal("check omitted its space diagnostics", err)
		}
		summary := object(t, summaries[0], "id", "policy", "policy_digest", "cursor", "diagnostic_count", "diagnostics")
		if text(t, summary["id"]) != p.id || text(t, summary["cursor"]) != badHead || string(summary["diagnostic_count"]) != "2" {
			t.Fatal("check omitted the forged head/count")
		}
		var checkDiagnostics []diagnostic
		if err := json.Unmarshal(summary["diagnostics"], &checkDiagnostics); err != nil {
			t.Fatal(err)
		}
		forgeryDiagnostics(t, checkDiagnostics, want, badHead)
		spaces, _ := readSpaces(t, a.read("recall", 0))
		if len(spaces) != 1 || spaces[0].Cursor != badHead || len(spaces[0].Views) != 0 || len(spaces[0].Diagnostics) != 2 {
			t.Fatal("forged push not excluded with exact diagnostic count")
		}
		forgeryDiagnostics(t, spaces[0].Diagnostics, want, badHead)
		if bytes.Contains(a.read("recall", 0).Data, []byte("forged-content-must-never-be-recalled")) {
			t.Fatal("forged content leaked into recall")
		}
	}
}

// This is an independently constructed adversarial wire record, not an admission
// API or a positive write shortcut. Zero signature bytes deliberately cannot
// authenticate the registered author; the other key is absent from the policy.
func forgedRecord(space, id, submitter, key string) []byte {
	record := map[string]any{
		"envelope": map[string]any{
			"id": id, "version": 1, "kind": "assertion", "schema": map[string]any{"id": "schema:assumption", "version": 1},
			"subject": submitter, "issuer": submitter, "submitter": submitter, "representation_ref": nil,
			"perspective": map[string]any{"kind": "own", "principal": submitter}, "admission_class": "machine_observation", "space": space,
			"valid":        map[string]any{"kind": "known", "from": "2026-10-01T00:00:00Z", "to": nil, "precision": "second"},
			"confirmed_at": "2026-10-19T00:00:00Z", "recorded": map[string]any{"sequence": 1, "at": "2026-10-19T00:00:00Z"},
			"lineage": "unknown", "context": "real",
			"disclosure": map[string]any{"audiences": []string{"aud:private", "aud:public"}, "purposes": []string{"purpose:read"}, "field_classes": []string{"public"}, "retain_until": nil, "declassification": []any{}},
		},
		"body": map[string]any{"statement_kind": "fact", "slot": "[]", "content": []any{map[string]any{"field": "value", "value": "forged-content-must-never-be-recalled"}}, "authority_receipt": nil},
	}
	wire, err := json.Marshal(map[string]any{"record": record, "signature": map[string]any{"purpose": "swarma-memory-record/1", "key": key, "alg": "ed25519", "value": base64.StdEncoding.EncodeToString(make([]byte, 64))}})
	if err != nil {
		panic(err) // All fixture values above are JSON primitives.
	}
	return wire
}

// Scenario 3: a rewind to genesis preserves the last verified view and cursor
// (including grants absent at genesis), reports exit 4, and recovers on restore.
// Phase A compares empty views; nonempty record preservation belongs to phase B.
func TestPhaseAHistoryRewrite(t *testing.T) {
	f := newFixture(t)
	p := f.project("space:project", "project")
	head := f.owner.git(p.remote, "rev-parse", "main")
	baseline := map[*agent]json.RawMessage{}
	for _, a := range []*agent{f.a, f.b} {
		clean(t, a, p, head)
		baseline[a] = a.read("recall", 0).Data
	}
	f.owner.git(p.remote, "update-ref", "refs/heads/main", p.genesis, head)
	for _, a := range []*agent{f.a, f.b} {
		refused(t, a.run(4, "sync"), "history_rewritten")
		r := a.read("recall", 4)
		refused(t, r, "history_rewritten")
		if !bytes.Equal(baseline[a], r.Data) {
			t.Fatal("rewrite changed last verified data/cursor")
		}
		if after := f.owner.git(p.remote, "rev-parse", "main"); after != p.genesis {
			t.Fatal("reader changed remote history")
		}
	}
	f.owner.git(p.remote, "update-ref", "refs/heads/main", head, p.genesis)
	for _, a := range []*agent{f.a, f.b} {
		clean(t, a, p, head)
		if !bytes.Equal(baseline[a], a.read("recall", 0).Data) {
			t.Fatal("restored history did not recover")
		}
	}
}

// Scenario 4: current signed reader revocation blocks B's recall and changes
// immediately while A still reads; regrant restores B, without a public fallback.
func TestPhaseAReaderRevocation(t *testing.T) {
	f := newFixture(t)
	p := f.project("space:project", "project")
	for _, a := range []*agent{f.a, f.b} {
		a.read("recall", 0)
		a.read("changes", 0)
	}
	f.owner.run(0, "policy", "revoke", "--space", p.id, "--identity", f.b.identity, "--role", "reader")
	for _, command := range []string{"recall", "changes"} {
		r := f.b.read(command, 3)
		refused(t, r, "not_authorized")
		if string(r.Data) != "null" {
			t.Fatal("revoked reader received partial data")
		}
		spaces, _ := readSpaces(t, f.a.read(command, 0))
		if len(spaces) != 1 || spaces[0].ID != p.id {
			t.Fatal("revocation affected the other agent")
		}
	}
	f.owner.run(0, "policy", "grant", "--space", p.id, "--identity", f.b.identity, "--role", "reader")
	for _, command := range []string{"recall", "changes"} {
		spaces, _ := readSpaces(t, f.b.read(command, 0))
		if len(spaces) != 1 || spaces[0].ID != p.id {
			t.Fatal("regrant did not restore read authority")
		}
	}
	f.verifyCommits(p)
}

// Scenario 5: one recall selects both readable spaces in stable ID order, with
// independent current commit cursors; selecting either space is the control.
// This checks empty-space aggregation, not a union of admitted record contents.
func TestPhaseATwoReadableSpaces(t *testing.T) {
	f := newFixture(t)
	z := f.project("space:zulu", "zulu")
	a := f.project("space:alpha", "alpha")
	for _, reader := range []*agent{f.a, f.b} {
		for _, p := range []project{z, a} {
			clean(t, reader, p, f.owner.git(p.remote, "rev-parse", "main"))
			r := reader.run(0, "recall", "*", "--space", p.id, "--at", "2026-10-19T00:00:00Z")
			spaces, _ := readSpaces(t, r)
			if len(spaces) != 1 || spaces[0].ID != p.id {
				t.Fatal("single-space control failed")
			}
		}
		result := reader.read("recall", 0)
		spaces, cursors := readSpaces(t, result)
		if len(spaces) != 2 || spaces[0].ID != a.id || spaces[1].ID != z.id || cursors[a.id] == cursors[z.id] {
			t.Fatal("spaces not independently ordered/cursored")
		}
		for _, p := range []project{a, z} {
			if cursors[p.id] != f.owner.git(p.remote, "rev-parse", "main") {
				t.Fatal("stale/crossed space cursor")
			}
		}
		if !bytes.Equal(result.Data, reader.read("recall", 0).Data) {
			t.Fatal("same synced state/logical time changed output")
		}
		data := object(t, result.Data, "cursor", "spaces")
		reader.run(0, "changes", "--since", text(t, data["cursor"]), "--at", "2026-10-19T00:00:00Z")
	}
}

// The test-side closed-output checker detects unknown/missing/duplicate fields
// and multiple documents; a complete valid object is the acceptance control.
func TestClosedOutputCheckerControls(t *testing.T) {
	for _, raw := range []string{`{"one":null,"extra":0}`, `{}`, `{"one":0,"one":1}`, `{"one":0} {"one":1}`, `[]`, "{\"one\":\"\xff\"}"} {
		if _, err := closedObject([]byte(raw), "one"); err == nil {
			t.Fatalf("accepted malformed output %s", raw)
		}
	}
	if _, err := closedObject([]byte(`{"one":null}`), "one"); err != nil {
		t.Fatal(err)
	}
}
