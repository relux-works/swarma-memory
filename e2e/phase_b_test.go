package e2e_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const queryTime = "2026-10-19T00:00:00Z"
const intakeTime = "2026-10-18T22:00:00Z"

type recordRef struct {
	ID      string `json:"id"`
	Version int    `json:"version"`
}

func array(t *testing.T, raw json.RawMessage) []json.RawMessage {
	t.Helper()
	var rows []json.RawMessage
	if err := json.Unmarshal(raw, &rows); err != nil || rows == nil {
		t.Fatalf("expected non-null array: %s (%v)", raw, err)
	}
	return rows
}

func ref(t *testing.T, raw json.RawMessage) recordRef {
	t.Helper()
	object(t, raw, "id", "version")
	var r recordRef
	if err := json.Unmarshal(raw, &r); err != nil || r.ID == "" || r.Version < 1 {
		t.Fatal("invalid ref", string(raw), err)
	}
	return r
}

func refs(t *testing.T, raw json.RawMessage) []recordRef {
	t.Helper()
	result := []recordRef{}
	for _, row := range array(t, raw) {
		result = append(result, ref(t, row))
	}
	return result
}

// These are literal public view/item fields, independent of production types.
// Fresh authorization handles must remain absent from the CLI data projection.
func readItems(t *testing.T, r reply, space string) []map[string]json.RawMessage {
	t.Helper()
	spaces, _ := readSpaces(t, r)
	result := []map[string]json.RawMessage{}
	for _, s := range spaces {
		if len(s.Diagnostics) != 0 {
			t.Fatal("unexpected read diagnostics", s.Diagnostics)
		}
		for _, raw := range s.Views {
			v := object(t, raw, "type", "semantic_profile", "projection_rule", "evidence_policy", "policy", "data_classification", "items", "currentness", "historical", "review_required", "explanation", "cutoffs", "changes")
			object(t, v["changes"], "state", "refs")
			explanation := object(t, v["explanation"], "status", "paths", "reason")
			for _, path := range array(t, explanation["paths"]) {
				refs(t, path)
			}
			for _, rawItem := range array(t, v["items"]) {
				i := object(t, rawItem, "ref", "subject", "issuer", "submitter", "perspective", "representation_ref", "admission_class", "statement_kind", "content", "valid", "confirmed_at", "usable_until", "currentness", "authority_receipt", "incompatible_with", "needs_review", "source_refs", "support", "oppose", "data_classification", "source", "write_token")
				ref(t, i["ref"])
				object(t, i["perspective"], "kind", "principal")
				for _, c := range array(t, i["content"]) {
					object(t, c, "field", "value")
				}
				for _, polarity := range []string{"support", "oppose"} {
					object(t, i[polarity], "witness", "evaluation", "corpus_coverage", "premise_quality", "evidence_qualification", "source_state", "freshness", "dependency_coverage", "witness_roots", "independent_root_count")
				}
				source := object(t, i["source"], "space", "cursor", "refs")
				if text(t, i["data_classification"]) != "data" || text(t, source["space"]) != s.ID || text(t, source["cursor"]) != s.Cursor || !reflect.DeepEqual(refs(t, source["refs"]), refs(t, i["source_refs"])) || !strings.HasPrefix(text(t, i["write_token"]), "write:1:") {
					t.Fatal("unattributed item or missing observed precondition", i)
				}
				if s.ID == space {
					result = append(result, i)
				}
			}
		}
	}
	return result
}

func item(t *testing.T, r reply, space, id string, version int) map[string]json.RawMessage {
	t.Helper()
	var found map[string]json.RawMessage
	for _, i := range readItems(t, r, space) {
		if ref(t, i["ref"]) == (recordRef{id, version}) {
			if found != nil {
				t.Fatal("duplicate item", id, version)
			}
			found = i
		}
	}
	if found == nil {
		t.Fatalf("missing %s@%d in %s", id, version, r.raw)
	}
	return found
}

func content(t *testing.T, i map[string]json.RawMessage, want string) {
	t.Helper()
	rows := array(t, i["content"])
	if len(rows) != 1 {
		t.Fatal("unexpected content", i)
	}
	c := object(t, rows[0], "field", "value")
	if text(t, c["field"]) != "value" || text(t, c["value"]) != want {
		t.Fatal("wrong content", string(i["content"]))
	}
}

func writeResult(t *testing.T, r reply, id string, version int, wantRefs int) string {
	t.Helper()
	d := object(t, r.Data, "id", "version", "commit", "cursor", "receipt")
	receipt := object(t, d["receipt"], "type", "operation", "outcome", "receipt_handle", "refs", "custody", "erasure_status")
	if text(t, d["id"]) != id || string(d["version"]) != strconv.Itoa(version) || text(t, d["commit"]) != text(t, d["cursor"]) || len(refs(t, receipt["refs"])) != wantRefs || text(t, receipt["receipt_handle"]) == "" {
		t.Fatal("unexpected write result", string(r.Data))
	}
	primary := recordRef{id, version}
	found := false
	for _, v := range refs(t, receipt["refs"]) {
		if v == primary {
			found = true
		}
	}
	if !found {
		t.Fatal("receipt omits primary output")
	}
	return text(t, d["commit"])
}

func readAt(a *agent, command, target, space string) reply {
	return a.run(0, command, target, "--space", space, "--at", queryTime)
}

func add(a *agent, p project, id, value string) reply {
	return a.run(0, "add", "assertion", "--space", p.id, "--id", id, "--content", value, "--idempotency-key", "add:"+id, "--at", intakeTime)
}

// A refusal cannot publish, create a local commit (even in reflog), change the
// index or dirty records. Reads/syncs happen before the snapshot, not inside it.
type publicationState struct{ Remote, Head, Tree, Index, Status, Reflog string }

func state(a *agent, p project) publicationState {
	clone := clonePath(a, p)
	return publicationState{
		a.git(p.remote, "rev-parse", "main"), a.git(clone, "rev-parse", "HEAD"),
		a.git(clone, "rev-parse", "HEAD^{tree}"), a.git(clone, "write-tree"),
		a.git(clone, "status", "--porcelain", "--untracked-files=all"),
		a.git(clone, "rev-list", "--all", "--reflog", "--count"),
	}
}

func unchanged(t *testing.T, before publicationState, a *agent, p project) {
	t.Helper()
	if after := state(a, p); before != after {
		t.Fatalf("refusal changed publication state: before=%+v after=%+v", before, after)
	}
}

// Scenarios 6/8/10: a documentary decision is attributed and source-linked;
// non-issuer and stale-precondition revisions publish nothing, issuer replace
// becomes current, and changes contains exactly the subsequent assertion refs.
// This is an observation about a decision, not receipt-backed decision authority.
func TestPhaseBDecisionRevisionAndChanges(t *testing.T) {
	f := newFixture(t)
	p := f.project("project:decision", "decision")
	id := "record:decision"
	excerpt := "Decision rationale from the working session.\n"
	added := f.a.start(excerpt, "add", "assertion", "--space", p.id, "--id", id, "--content", "Decision: use the bounded local queue", "--idempotency-key", "decision:one", "--source-session", "runtime:planning:message:42", "--source-text", "-", "--at", intakeTime).finish(0)
	head := writeResult(t, added, id, 1, 3)
	clean(t, f.b, p, head)
	baseline := readAt(f.b, "recall", "*", p.id)
	i := item(t, baseline, p.id, id, 1)
	content(t, i, "Decision: use the bounded local queue")
	source := recordRef{id + ":source", 1}
	if text(t, i["issuer"]) != f.a.identity || !reflect.DeepEqual(refs(t, i["source_refs"]), []recordRef{source}) {
		t.Fatal("decision lost issuer/source", i)
	}
	explained := item(t, readAt(f.b, "explain", id, p.id), p.id, id, 1)
	if text(t, explained["issuer"]) != f.a.identity || !reflect.DeepEqual(refs(t, explained["source_refs"]), []recordRef{source}) {
		t.Fatal("explain lost attribution")
	}
	cursor := text(t, object(t, baseline.Data, "cursor", "spaces")["cursor"])

	before := state(f.b, p)
	denied := f.b.run(3, "revise", id, "--space", p.id, "--relation", "replace", "--content", "Non-issuer replacement", "--expected-version", strconv.Itoa(ref(t, explained["ref"]).Version), "--idempotency-key", "deny:issuer", "--at", intakeTime)
	refused(t, denied, "representation_invalid")
	unchanged(t, before, f.b, p)
	own := item(t, readAt(f.a, "explain", id, p.id), p.id, id, 1)
	before = state(f.a, p)
	refused(t, f.a.run(2, "revise", id, "--space", p.id, "--relation", "replace", "--content", "Missing precondition", "--idempotency-key", "deny:no-precondition", "--at", intakeTime), "usage")
	unchanged(t, before, f.a, p)
	revised := f.a.run(0, "revise", id, "--space", p.id, "--relation", "replace", "--content", "Decision: use the bounded durable queue", "--expected-token", text(t, own["write_token"]), "--idempotency-key", "decision:two", "--at", intakeTime)
	head = writeResult(t, revised, id, 2, 2)
	clean(t, f.b, p, head)
	current := readAt(f.b, "recall", "*", p.id)
	replacement := item(t, current, p.id, id, 2)
	content(t, replacement, "Decision: use the bounded durable queue")
	if text(t, replacement["currentness"]) != "current" || len(readItems(t, current, p.id)) != 1 {
		t.Fatal("replacement not uniquely current", string(current.Data))
	}

	// Reusing a caller-observed old version must not silently retarget version 2.
	before = state(f.a, p)
	refused(t, f.a.run(3, "revise", id, "--space", p.id, "--relation", "replace", "--content", "Stale replacement", "--expected-version", strconv.Itoa(ref(t, own["ref"]).Version), "--idempotency-key", "deny:stale", "--at", intakeTime), "version_conflict")
	unchanged(t, before, f.a, p)
	writeResult(t, add(f.b, p, "record:later", "Later queue observation"), "record:later", 1, 1)
	changes := f.b.run(0, "changes", "--space", p.id, "--since", cursor, "--at", queryTime)
	assertChanges(t, changes, map[string][]recordRef{p.id: {{id, 2}, {"record:later", 1}}})
	lastCursor := text(t, object(t, changes.Data, "cursor", "spaces")["cursor"])
	assertChanges(t, f.b.run(0, "changes", "--space", p.id, "--since", lastCursor, "--at", queryTime), map[string][]recordRef{p.id: {}})
	before = state(f.b, p)
	refused(t, f.b.run(3, "changes", "--space", p.id, "--since", "memory:1:invalid", "--at", queryTime), "invalid_cursor")
	unchanged(t, before, f.b, p)
	if a, b := f.a.read("recall", 0), f.b.read("recall", 0); !bytes.Equal(a.raw, b.raw) {
		t.Fatal("readers differ after revision and later add")
	}
	f.verifyCommits(p)
}

func assertChanges(t *testing.T, r reply, want map[string][]recordRef) {
	t.Helper()
	readItems(t, r, "")
	spaces, _ := readSpaces(t, r)
	got := map[string][]recordRef{}
	for _, s := range spaces {
		got[s.ID] = []recordRef{}
		seen := map[recordRef]bool{}
		for _, raw := range s.Views {
			var v map[string]json.RawMessage
			if err := json.Unmarshal(raw, &v); err != nil {
				t.Fatal(err)
			}
			c := object(t, v["changes"], "state", "refs")
			rs := refs(t, c["refs"])
			switch text(t, c["state"]) {
			case "changed":
				if len(rs) == 0 {
					t.Fatal("changed fixture view has no changed refs", string(raw))
				}
			case "no_change":
				if len(rs) != 0 {
					t.Fatal("unchanged view reports changed refs", string(raw))
				}
			default:
				t.Fatal("cursor comparison returned an initial/unknown change state", string(raw))
			}
			for _, ref := range rs {
				if seen[ref] {
					t.Fatal("duplicate changed ref", ref)
				}
				seen[ref] = true
				got[s.ID] = append(got[s.ID], ref)
			}
		}
	}
	normalize := func(m map[string][]recordRef) {
		for _, rs := range m {
			sort.Slice(rs, func(i, j int) bool {
				if rs[i].ID == rs[j].ID {
					return rs[i].Version < rs[j].Version
				}
				return rs[i].ID < rs[j].ID
			})
		}
	}
	normalize(got)
	normalize(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("changes refs: got %v want %v", got, want)
	}
}

// Scenario 7: independently keyed homes for ONE registered issuer race real
// version-1 replacements. Distinct issuers cannot both replace that sequence;
// their separate refusal contract is exercised in scenario 8 above.
func TestPhaseBConcurrentRevision(t *testing.T) {
	f := &fixture{t: t, root: t.TempDir()}
	f.allowedSigners = filepath.Join(f.root, "allowed_signers")
	f.owner = f.newAgent("owner")
	f.a = f.newAgentIdentity("a", "agent:writer")
	f.b = f.newAgentIdentity("b", "agent:writer")
	p := f.project("project:race", "race")
	id := "record:race"
	parent := writeResult(t, add(f.a, p, id, "Initial value"), id, 1, 1)
	clean(t, f.b, p, parent)
	observed := []map[string]json.RawMessage{item(t, readAt(f.a, "explain", id, p.id), p.id, id, 1), item(t, readAt(f.b, "explain", id, p.id), p.id, id, 1)}
	barrier := filepath.Join(f.root, "barrier")
	hooks := filepath.Join(f.root, "hooks")
	for _, dir := range []string{barrier, hooks} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	// A bounded fixture-owned pre-push barrier proves both signed candidates have
	// the same parent. It changes timing only, never admission or push semantics.
	script := "#!/bin/sh\nbarrier='" + strings.ReplaceAll(barrier, "'", "'\"'\"'") + "'\n" + `
if [ -f "$barrier/released" ]; then exit 0; fi
git rev-parse HEAD^ > "$barrier/parent-$$" || exit 81
if mkdir "$barrier/first" 2>/dev/null; then
 i=0
 while [ ! -f "$barrier/released" ]; do
  i=$((i + 1))
  if [ "$i" -gt 2000 ]; then exit 82; fi
  sleep 0.01
 done
else
 : > "$barrier/released"
fi
`
	if err := os.WriteFile(filepath.Join(hooks, "pre-push"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	agents := []*agent{f.a, f.b}
	calls := []*invocation{}
	for n, a := range agents {
		for i, entry := range a.env {
			if strings.HasPrefix(entry, "GIT_CONFIG_VALUE_4=") {
				a.env[i] = "GIT_CONFIG_VALUE_4=" + hooks
			}
		}
		calls = append(calls, a.start("", "revise", id, "--space", p.id, "--relation", "replace", "--content", "Candidate "+strconv.Itoa(n), "--expected-version", strconv.Itoa(ref(t, observed[n]["ref"]).Version), "--idempotency-key", "race:"+strconv.Itoa(n), "--at", intakeTime))
	}
	loser, winner := -1, -1
	for n, c := range calls {
		r := c.finish(-1)
		if r.Error != nil {
			refused(t, r, "version_conflict")
			if loser != -1 {
				t.Fatal("both candidates lost")
			}
			loser = n
		} else {
			if winner != -1 {
				t.Fatal("both candidates won")
			}
			winner = n
			writeResult(t, r, id, 2, 2)
		}
	}
	if loser < 0 || winner < 0 || f.owner.git(p.remote, "rev-list", "--count", parent+"..main") != "1" {
		t.Fatal("race did not publish exactly one revision")
	}
	parents, err := filepath.Glob(filepath.Join(barrier, "parent-*"))
	if err != nil || len(parents) != 2 {
		t.Fatal("race did not reach two real pushes", parents, err)
	}
	for _, file := range parents {
		raw, err := os.ReadFile(file)
		if err != nil || strings.TrimSpace(string(raw)) != parent {
			t.Fatal("candidates did not extend the same parent", err)
		}
	}
	for _, a := range agents {
		s := state(a, p)
		if s.Status != "" || s.Head != s.Remote || s.Tree != s.Index {
			t.Fatal("race left an unpublished head/index/tree", s)
		}
	}
	retrying := agents[loser]
	fresh := item(t, readAt(retrying, "explain", id, p.id), p.id, id, 2)
	content(t, fresh, "Candidate "+strconv.Itoa(winner))
	head := writeResult(t, retrying.run(0, "revise", id, "--space", p.id, "--relation", "replace", "--content", "Retry from the winner", "--expected-token", text(t, fresh["write_token"]), "--idempotency-key", "race:retry", "--at", intakeTime), id, 3, 2)
	if f.owner.git(p.remote, "rev-list", "--count", parent+"..main") != "2" {
		t.Fatal("retry did not publish exactly once")
	}
	for _, a := range agents {
		clean(t, a, p, head)
	}
	ra, rb := f.a.read("recall", 0), f.b.read("recall", 0)
	content(t, item(t, rb, p.id, id, 3), "Retry from the winner")
	if !bytes.Equal(ra.raw, rb.raw) {
		t.Fatal("race readers are not byte-identical")
	}
	f.verifyCommits(p)
}

// Scenario 9: targeted model assessment uses a caller-observed token; absent
// writer authority cannot publish, and assessment alone invents no evidence
// witness. Promotion requires source read and target
// write independently, then creates a locally attributed derivative in space 2.
func TestPhaseBAssessAndPromote(t *testing.T) {
	f := newFixture(t)
	source, target := f.project("project:source", "source"), f.project("project:target", "target")
	id := "record:original"
	writeResult(t, add(f.a, source, id, "Promotable queue observation"), id, 1, 1)
	observed := item(t, readAt(f.b, "explain", id, source.id), source.id, id, 1)
	f.owner.run(0, "policy", "revoke", "--space", source.id, "--identity", f.b.identity, "--role", "writer")
	f.b.run(0, "sync", "--space", source.id)
	before := state(f.b, source)
	refused(t, f.b.run(3, "assess", id, "--space", source.id, "--kind", "semantic_review", "--expected-version", strconv.Itoa(ref(t, observed["ref"]).Version), "--id", "record:assessment", "--idempotency-key", "deny:assessment", "--at", intakeTime), "not_authorized")
	unchanged(t, before, f.b, source)
	f.owner.run(0, "policy", "grant", "--space", source.id, "--identity", f.b.identity, "--role", "writer")
	observed = item(t, readAt(f.b, "explain", id, source.id), source.id, id, 1)
	assessmentHead := writeResult(t, f.b.run(0, "assess", id, "--space", source.id, "--kind", "semantic_review", "--expected-token", text(t, observed["write_token"]), "--id", "record:assessment", "--idempotency-key", "assessment:one", "--at", intakeTime), "record:assessment", 1, 1)
	clean(t, f.a, source, assessmentHead)
	clean(t, f.b, source, assessmentHead)
	assessed := item(t, readAt(f.a, "explain", id, source.id), source.id, id, 1)
	support := object(t, assessed["support"], "witness", "evaluation", "corpus_coverage", "premise_quality", "evidence_qualification", "source_state", "freshness", "dependency_coverage", "witness_roots", "independent_root_count")
	if text(t, support["witness"]) != "not_found" || len(array(t, support["evidence_qualification"])) != 0 {
		t.Fatal("assessment alone fabricated a qualified evidence witness", string(assessed["support"]))
	}

	promote := []string{"promote", id, "--space", source.id, "--to", target.id, "--id", "record:derived", "--idempotency-key", "promotion:one", "--at", intakeTime}
	f.owner.run(0, "policy", "revoke", "--space", source.id, "--identity", f.b.identity, "--role", "reader")
	f.b.run(0, "sync")
	before = state(f.b, target)
	refused(t, f.b.run(3, promote...), "not_authorized")
	unchanged(t, before, f.b, target)
	f.owner.run(0, "policy", "grant", "--space", source.id, "--identity", f.b.identity, "--role", "reader")
	f.owner.run(0, "policy", "revoke", "--space", target.id, "--identity", f.b.identity, "--role", "writer")
	f.b.run(0, "sync")
	before = state(f.b, target)
	refused(t, f.b.run(3, promote...), "not_authorized")
	unchanged(t, before, f.b, target)
	f.owner.run(0, "policy", "grant", "--space", target.id, "--identity", f.b.identity, "--role", "writer")
	promoted := f.b.run(0, promote...)
	head := writeResult(t, promoted, "record:derived", 1, 3)
	clean(t, f.a, target, head)
	all := f.a.read("recall", 0)
	original := item(t, all, source.id, id, 1)
	derived := item(t, all, target.id, "record:derived", 1)
	content(t, derived, "Promotable queue observation")
	if text(t, original["issuer"]) != f.a.identity || text(t, derived["issuer"]) != f.b.identity || !reflect.DeepEqual(refs(t, derived["source_refs"]), []recordRef{{"record:derived:source", 1}}) {
		t.Fatal("promotion lost attribution/citation")
	}
	retry := f.b.run(0, promote...)
	// Exact replay must retain publication identity and receipt, rather than append.
	if !bytes.Equal(retry.Data, promoted.Data) || state(f.b, target).Remote != head {
		t.Fatal("promotion replay appended a commit")
	}
	if a, b := f.a.read("recall", 0), f.b.read("recall", 0); !bytes.Equal(a.raw, b.raw) {
		t.Fatal("multi-space readers differ")
	}
	f.verifyCommits(source)
	f.verifyCommits(target)
}

// Scenario 11 (v1): B sees A's exact session-source ref in recall/explain,
// and check verifies the atomic signed batch containing that source. Revoking
// space read access hides all data/refs; A still reads, and regrant restores B.
// This does not claim per-record filtering or locator/excerpt presentation.
func TestPhaseBSessionSource(t *testing.T) {
	f := newFixture(t)
	p := f.project("project:session", "session")
	id := "record:session-observation"
	source := recordRef{id + ":source", 1}
	excerpt := "The session selected a bounded queue.\nPreserve this trailing newline.\n"
	before := state(f.a, p)
	refused(t, f.a.start(excerpt, "add", "assertion", "--space", p.id, "--content", "Malformed session control", "--idempotency-key", "deny:session", "--source-session", "runtime:session", "--source-text", "-", "--at", intakeTime).finish(2), "usage")
	unchanged(t, before, f.a, p)
	added := f.a.start(excerpt, "add", "assertion", "--space", p.id, "--id", id, "--content", "Session observation", "--idempotency-key", "session:one", "--source-session", "runtime:planning:message:42", "--source-text", "-", "--at", intakeTime).finish(0)
	head := writeResult(t, added, id, 1, 3)
	data := object(t, added.Data, "id", "version", "commit", "cursor", "receipt")
	receipt := object(t, data["receipt"], "type", "operation", "outcome", "receipt_handle", "refs", "custody", "erasure_status")
	expectedRefs := map[recordRef]bool{{id, 1}: true, source: true, {id + ":basis", 1}: true}
	for _, r := range refs(t, receipt["refs"]) {
		if !expectedRefs[r] {
			t.Fatal("unexpected or duplicate batch ref", r)
		}
		delete(expectedRefs, r)
	}
	if len(expectedRefs) != 0 {
		t.Fatal("receipt omits a signed batch ref", expectedRefs)
	}
	clean(t, f.b, p, head)
	assertSource := func(a *agent) {
		t.Helper()
		for _, r := range []reply{readAt(a, "recall", "*", p.id), readAt(a, "explain", id, p.id)} {
			i := item(t, r, p.id, id, 1)
			content(t, i, "Session observation")
			if text(t, i["issuer"]) != f.a.identity || !reflect.DeepEqual(refs(t, i["source_refs"]), []recordRef{source}) {
				t.Fatal("session assertion lost issuer/source ref")
			}
		}
	}
	assertSource(f.b)
	f.owner.run(0, "policy", "revoke", "--space", p.id, "--identity", f.b.identity, "--role", "reader")
	f.b.run(0, "sync", "--space", p.id)
	before = state(f.b, p)
	for _, args := range [][]string{{"recall", "*"}, {"explain", id}} {
		r := f.b.run(3, append(args, "--space", p.id, "--at", queryTime)...)
		refused(t, r, "not_authorized")
		if string(r.Data) != "null" || bytes.Contains(r.raw, []byte(source.ID)) {
			t.Fatal("no-access reader received source data/ref", string(r.raw))
		}
	}
	unchanged(t, before, f.b, p)
	assertSource(f.a)
	f.owner.run(0, "policy", "grant", "--space", p.id, "--identity", f.b.identity, "--role", "reader")
	clean(t, f.b, p, f.owner.git(p.remote, "rev-parse", "main"))
	assertSource(f.b)
	if a, b := f.a.read("recall", 0), f.b.read("recall", 0); !bytes.Equal(a.raw, b.raw) {
		t.Fatal("source readers differ after regrant")
	}
	f.verifyCommits(p)
}
