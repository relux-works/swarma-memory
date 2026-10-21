package e2e_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func stage6Packet(t *testing.T, r reply, embedded bool) map[string]json.RawMessage {
	t.Helper()
	raw := r.Data
	if embedded {
		raw = object(t, raw, "cursor", "spaces", "escalation")["escalation"]
	}
	p := object(t, raw, "format", "data_classification", "reporter", "dependent", "conflicts")
	if text(t, p["format"]) != "swarma-memory-escalation/1" || text(t, p["data_classification"]) != "data" {
		t.Fatal("packet boundary", string(raw))
	}
	object(t, p["dependent"], "task", "step")
	for _, raw := range array(t, p["conflicts"]) {
		c := object(t, raw, "conflict_key", "kind", "space", "commit", "policy", "items", "evidence", "area", "resolvers", "resolver_basis")
		object(t, c["policy"], "version", "digest")
		object(t, c["evidence"], "support", "oppose", "incompatible_with")
		for _, i := range array(t, c["items"]) {
			m := object(t, i, "ref", "subject", "schema", "issuer", "currentness")
			ref(t, m["ref"])
			ref(t, m["schema"])
		}
	}
	return p
}
func stage6Conflict(t *testing.T, p map[string]json.RawMessage) map[string]json.RawMessage {
	t.Helper()
	cs := array(t, p["conflicts"])
	if len(cs) != 1 {
		t.Fatal("expected one conflict", string(p["conflicts"]))
	}
	return object(t, cs[0], "conflict_key", "kind", "space", "commit", "policy", "items", "evidence", "area", "resolvers", "resolver_basis")
}
func stage6Named(t *testing.T, c map[string]json.RawMessage, owner string) {
	t.Helper()
	var ids []string
	json.Unmarshal(c["resolvers"], &ids)
	if text(t, c["area"]) != "queue-design" || text(t, c["resolver_basis"]) != "named" || !reflect.DeepEqual(ids, []string{owner}) {
		t.Fatal("wrong route", c)
	}
}

// Stage 6: real signed Git/CLI evidence conflict blocks only the exact dependent
// step. A separate shell caller publishes neither its write nor effect file on
// exit 7, and resumes after the issuer replaces the observed version. D is an
// attributed decision statement, never a receipt-backed external decision.
func TestStage6ConflictEscalation(t *testing.T) {
	f := newFixture(t)
	p := f.project("project:stage6", "stage6")
	w := f.newAgent("worker")
	f.owner.run(0, "keys", "register", "--space", p.id, "--identity", w.identity, "--public-key", w.publicKey)
	for _, role := range []string{"reader", "writer"} {
		f.owner.run(0, "policy", "grant", "--space", p.id, "--identity", w.identity, "--role", role)
	}
	w.run(0, "spaces", "add", p.id, "--remote", p.remote, "--genesis", p.pin)
	f.owner.run(0, "policy", "resolvers", "set", "--space", p.id, "--area", "queue-design", "--schemas", `[{"id":"schema:assumption","version":1}]`, "--subjects", `["topic:queue"]`, "--identities", `["agent:owner"]`)
	f.owner.run(0, "add", "assertion", "--space", p.id, "--id", "record:D", "--subject", "topic:queue", "--perspective", "team", "--perspective-principal", "team:queue", "--content", "Decision statement: use queue A", "--idempotency-key", "decision:one", "--at", intakeTime)
	for _, a := range []*agent{f.a, f.b} {
		polarity := "support"
		if a == f.b {
			polarity = "oppose"
		}
		a.run(0, "assess", "record:D", "--space", p.id, "--kind", "semantic_review", "--perspective", "team", "--perspective-principal", "team:queue", "--polarity", polarity, "--expected-version", "1", "--id", "assessment:"+polarity, "--idempotency-key", "review:"+polarity, "--at", intakeTime)
	}
	check := func(a *agent) reply {
		return a.run(7, "explain", "record:D", "--space", p.id, "--require-current", "--task", "task:dependent", "--step", "step:publish", "--at", queryTime)
	}
	first := stage6Conflict(t, stage6Packet(t, check(w), true))
	stage6Named(t, first, f.owner.identity)
	if text(t, first["kind"]) != "evidence_conflict" {
		t.Fatal("wrong evidence conflict kind")
	}
	recalled := stage6Conflict(t, stage6Packet(t, w.run(7, "recall", "*", "--space", p.id, "--subject", "topic:queue", "--schema", "schema:assumption", "--require-current", "--at", queryTime), true))
	if string(recalled["conflict_key"]) != string(first["conflict_key"]) {
		t.Fatal("exact recall and explain packets disagree")
	}
	w.run(0, "recall", "*", "--space", p.id, "--subject", "topic:queue:child", "--schema", "schema:assumption", "--require-current", "--at", queryTime)
	evidence := object(t, first["evidence"], "support", "oppose", "incompatible_with")
	if !reflect.DeepEqual(refs(t, evidence["support"]), []recordRef{{"assessment:support", 1}}) || !reflect.DeepEqual(refs(t, evidence["oppose"]), []recordRef{{"assessment:oppose", 1}}) {
		t.Fatal("wrong authorized evidence", evidence)
	}
	second := stage6Conflict(t, stage6Packet(t, check(f.a), true))
	if string(first["conflict_key"]) != string(second["conflict_key"]) {
		t.Fatal("reporter changed key")
	}
	direct := stage6Conflict(t, stage6Packet(t, w.run(7, "conflicts", "--space", p.id, "--id", "record:D", "--at", queryTime), false))
	if string(direct["conflict_key"]) != string(first["conflict_key"]) {
		t.Fatal("packet forms differ")
	}
	effect := filepath.Join(w.root, "dependent-effect")
	step := func(want int) {
		t.Helper()
		script := `"$MEMORY_BIN" --home "$MEMORY_HOME" --json explain record:D --space project:stage6 --require-current --at 2026-10-19T00:00:00Z || exit "$?"
"$MEMORY_BIN" --home "$MEMORY_HOME" --json add assertion --space project:stage6 --id record:dependent --content "Dependent work" --idempotency-key dependent:one --at 2026-10-18T22:00:00Z || exit "$?"
: > "$EFFECT_FILE"`
		cmd := exec.Command("/bin/sh", "-c", script)
		cmd.Dir = w.root
		cmd.Env = append(append([]string{}, w.env...), "MEMORY_BIN="+memoryBinary, "MEMORY_HOME="+w.home, "EFFECT_FILE="+effect)
		output, err := cmd.CombinedOutput()
		if cmd.ProcessState == nil || cmd.ProcessState.ExitCode() != want {
			t.Fatalf("dependent step exit: %v %s", err, output)
		}
	}
	before := f.owner.git(p.remote, "rev-parse", "main")
	step(7)
	if _, e := os.Stat(effect); !os.IsNotExist(e) || f.owner.git(p.remote, "rev-parse", "main") != before {
		t.Fatal("blocked step published")
	}
	// An unrelated subject does not stop this step, despite the existing conflict.
	f.owner.run(0, "add", "assertion", "--space", p.id, "--id", "record:other", "--subject", "topic:other", "--content", "Independent work", "--idempotency-key", "other:one", "--at", intakeTime)
	w.run(0, "explain", "record:other", "--space", p.id, "--require-current", "--at", queryTime)
	w.run(0, "recall", "*", "--space", p.id, "--subject", "topic:other", "--schema", "schema:assumption", "--require-current", "--at", queryTime)
	empty := stage6Packet(t, w.run(0, "conflicts", "--space", p.id, "--id", "record:other", "--at", queryTime), false)
	if len(array(t, empty["conflicts"])) != 0 {
		t.Fatal("unrelated conflict")
	}
	fallback := stage6Conflict(t, stage6Packet(t, w.run(7, "conflicts", "--ref", p.id+":record:other:1", "--at", queryTime), false))
	if text(t, fallback["resolver_basis"]) != "default_owners" {
		t.Fatal("missing owner fallback")
	}
	// Neither a third-party revision nor a new non-resolver assertion rewrites D.
	refused(t, f.b.run(3, "revise", "record:D", "--space", p.id, "--relation", "replace", "--content", "Forged ruling", "--expected-version", "1", "--idempotency-key", "deny:replace", "--at", intakeTime), "representation_invalid")
	check(w)
	add(f.b, p, "record:non-resolver-ruling", "An unrelated issuer's ruling")
	check(w)
	acceptRuling := func(id string) bool {
		t.Helper()
		ruling := item(t, w.run(0, "explain", id, "--space", p.id, "--require-current", "--at", queryTime), p.id, id, 1)
		var resolvers []string
		if e := json.Unmarshal(first["resolvers"], &resolvers); e != nil {
			t.Fatal(e)
		}
		for _, resolver := range resolvers {
			if text(t, ruling["issuer"]) == resolver {
				return true
			}
		}
		return false
	}
	if acceptRuling("record:non-resolver-ruling") {
		t.Fatal("non-resolver ruling satisfied caller resume rule")
	}
	// The named resolver may issue its own ruling; the caller explicitly repoints
	// to it only after matching its issuer to the blocked dependency's recipients.
	add(f.owner, p, "record:resolver-ruling", "Resolver's separate ruling")
	check(w)
	if !acceptRuling("record:resolver-ruling") {
		t.Fatal("named resolver ruling refused by caller resume rule")
	}
	// Failed policy edits publish nothing and leave the previous routing in force.
	before = f.owner.git(p.remote, "rev-parse", "main")
	refused(t, f.owner.run(3, "policy", "resolvers", "set", "--space", p.id, "--area", "overlap", "--subjects", `["topic:queue"]`, "--identities", `["agent:owner"]`), "resolver_overlap")
	if f.owner.git(p.remote, "rev-parse", "main") != before {
		t.Fatal("overlap published")
	}
	stage6Named(t, stage6Conflict(t, stage6Packet(t, check(w), true)), f.owner.identity)
	f.owner.run(0, "policy", "revoke", "--space", p.id, "--identity", f.b.identity, "--role", "writer")
	before = f.owner.git(p.remote, "rev-parse", "main")
	refused(t, f.owner.run(3, "policy", "resolvers", "set", "--space", p.id, "--area", "unqualified", "--subjects", `["topic:other"]`, "--identities", `["agent:b"]`), "resolver_unqualified")
	if f.owner.git(p.remote, "rev-parse", "main") != before {
		t.Fatal("unqualified policy published")
	}
	// The issuer's canonical local sequence replacement resolves this dependency;
	// the older attributed record and assessments are not overwritten.
	f.owner.run(0, "revise", "record:D", "--space", p.id, "--relation", "replace", "--content", "Decision statement: use queue B", "--expected-version", "1", "--idempotency-key", "decision:two", "--at", intakeTime)
	before = f.owner.git(p.remote, "rev-parse", "main")
	step(0)
	if f.owner.git(p.remote, "rev-parse", "main") == before {
		t.Fatal("resumed step did not publish a commit")
	}
	published := item(t, f.owner.run(0, "explain", "record:dependent", "--space", p.id, "--at", queryTime), p.id, "record:dependent", 1)
	if text(t, published["issuer"]) != w.identity {
		t.Fatal("remote dependent write has wrong issuer")
	}
	content(t, published, "Dependent work")
	if _, e := os.Stat(effect); e != nil {
		t.Fatal("resolved step did not run", e)
	}
	if strings.Contains(string(w.run(0, "conflicts", "--space", p.id, "--id", "record:D", "--at", queryTime).Data), `"kind":"evidence_conflict"`) {
		t.Fatal("stale conflict survived")
	}
	f.verifyCommits(p)
}

// Unequal rule facts in one team perspective are current for their separate
// issuers and incompatible. The exact dependency check must surface that ref;
// an adjacent subject remains an independent positive control.
func TestStage6Incompatible(t *testing.T) {
	f := newFixture(t)
	p := f.project("project:incompatible", "incompatible")
	write := func(a *agent, id, value string) {
		a.run(0, "add", "assertion", "--space", p.id, "--id", id, "--subject", "topic:rules", "--schema", "schema:rule", "--perspective", "team", "--perspective-principal", "team:queue", "--content", value, "--idempotency-key", id, "--at", intakeTime)
	}
	write(f.a, "record:rule-a", "capacity 64")
	f.b.run(0, "explain", "record:rule-a", "--space", p.id, "--require-current", "--at", queryTime)
	write(f.b, "record:rule-b", "capacity 128")
	c := stage6Conflict(t, stage6Packet(t, f.a.run(7, "explain", "record:rule-a", "--space", p.id, "--require-current", "--at", queryTime), true))
	if text(t, c["kind"]) != "incompatible" || !reflect.DeepEqual(refs(t, object(t, c["evidence"], "support", "oppose", "incompatible_with")["incompatible_with"]), []recordRef{{"record:rule-b", 1}}) {
		t.Fatal("wrong incompatibility", c)
	}
	add(f.a, p, "record:unrelated", "Unrelated statement")
	f.b.run(0, "explain", "record:unrelated", "--space", p.id, "--require-current", "--at", queryTime)
}

// A caller-reported contradiction keeps each owner's verified route, including
// two distinct routes inside one space. Ref order/duplication cannot change its
// one shared key, and reading the packet publishes no commits in either space.
func TestStage6ReportedRoutes(t *testing.T) {
	f := newFixture(t)
	p := f.project("project:local", "reported-local")
	q := project{id: "project:foreign", remote: filepath.Join(f.root, "reported-foreign.git")}
	f.a.git(f.root, "init", "--bare", "--initial-branch=main", q.remote)
	s := object(t, f.a.run(0, "spaces", "init", q.id, "--remote", q.remote).Data, "id", "policy", "policy_digest", "cursor", "diagnostic_count", "diagnostics")
	q.pin = text(t, s["policy_digest"])
	f.a.run(0, "keys", "register", "--space", q.id, "--identity", f.b.identity, "--public-key", f.b.publicKey)
	f.a.run(0, "policy", "grant", "--space", q.id, "--identity", f.b.identity, "--role", "reader")
	f.b.run(0, "spaces", "add", q.id, "--remote", q.remote, "--genesis", q.pin)
	f.owner.run(0, "policy", "resolvers", "set", "--space", p.id, "--area", "local-topic", "--subjects", `["topic:local"]`, "--identities", `["agent:owner"]`)
	show := object(t, f.owner.run(0, "policy", "resolvers", "show", "--space", p.id).Data, "resolvers", "warnings")
	if len(array(t, show["resolvers"])) != 1 || len(array(t, show["warnings"])) != 0 {
		t.Fatal("owner show lost resolver", show)
	}
	refused(t, f.b.run(3, "policy", "resolvers", "show", "--space", p.id), "unauthorized_owner")
	f.owner.run(0, "add", "assertion", "--space", p.id, "--id", "record:local", "--subject", "topic:local", "--content", "Local statement", "--idempotency-key", "reported:local", "--at", intakeTime)
	add(f.owner, p, "record:default", "Separate default route")
	add(f.a, q, "record:foreign", "Foreign owner's statement")
	beforeP, beforeQ := f.owner.git(p.remote, "rev-parse", "main"), f.a.git(q.remote, "rev-parse", "main")
	one, two, three := p.id+":record:local:1", p.id+":record:default:1", q.id+":record:foreign:1"
	read := func(args ...string) map[string]json.RawMessage {
		return stage6Packet(t, f.b.run(7, append([]string{"conflicts", "--at", queryTime}, args...)...), false)
	}
	first := read("--ref", one, "--ref", two, "--ref", three)
	second := read("--ref", three, "--ref", one, "--ref", two, "--ref", one)
	if string(first["conflicts"]) != string(second["conflicts"]) {
		t.Fatal("ref order changed packet")
	}
	blocks := array(t, first["conflicts"])
	if len(blocks) != 3 {
		t.Fatal("routes were dropped or conflated", string(first["conflicts"]))
	}
	key, previous := "", ""
	seen := map[string]bool{}
	for _, raw := range blocks {
		var c struct {
			Key       string   `json:"conflict_key"`
			Space     string   `json:"space"`
			Kind      string   `json:"kind"`
			Basis     string   `json:"resolver_basis"`
			Resolvers []string `json:"resolvers"`
			Items     []struct {
				Ref recordRef `json:"ref"`
			} `json:"items"`
		}
		if e := json.Unmarshal(raw, &c); e != nil {
			t.Fatal(e)
		}
		if key == "" {
			key = c.Key
		}
		if c.Key != key || c.Kind != "reported" || c.Space < previous || len(c.Items) != 1 {
			t.Fatal("bad report grouping", c)
		}
		previous = c.Space
		id := c.Items[0].Ref.ID
		seen[id] = true
		wantOwner, wantBasis := f.owner.identity, "default_owners"
		if id == "record:local" {
			wantBasis = "named"
		}
		if id == "record:foreign" {
			wantOwner = f.a.identity
		}
		if c.Basis != wantBasis || !reflect.DeepEqual(c.Resolvers, []string{wantOwner}) {
			t.Fatal("wrong owner route", c)
		}
	}
	if len(seen) != 3 || beforeP != f.owner.git(p.remote, "rev-parse", "main") || beforeQ != f.a.git(q.remote, "rev-parse", "main") {
		t.Fatal("read changed spaces or lost refs")
	}
	// Only the owner can remove routing. An unknown label cannot publish a no-op.
	f.owner.run(0, "policy", "resolvers", "remove", "--space", p.id, "--area", "local-topic")
	removed := stage6Conflict(t, read("--ref", one))
	if text(t, removed["resolver_basis"]) != "default_owners" {
		t.Fatal("removed route survived")
	}
	beforeP = f.owner.git(p.remote, "rev-parse", "main")
	refused(t, f.owner.run(3, "policy", "resolvers", "remove", "--space", p.id, "--area", "missing"), "record_not_found")
	if f.owner.git(p.remote, "rev-parse", "main") != beforeP {
		t.Fatal("missing removal published")
	}

}
