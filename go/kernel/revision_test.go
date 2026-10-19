package kernel

import (
	"reflect"
	"testing"
)

func authorizeProposal(snapshot map[string]any, r any) {
	p := obj(snapshot["policy"])
	p["lineage_facts"] = append(arr(p["lineage_facts"]), map[string]any{"output": ref(r), "profile": map[string]any{"id": "integration:synthetic", "version": int64(1)}, "kind": "direct", "inputs": []any{}, "complete": true})
	p["reviews"] = append(arr(p["reviews"]), map[string]any{"record": ref(r), "reviewer": "subj:h1", "result": "allow"})
}

// TestSingleSequenceAdmission proves ordinary single slots cannot fork by plain
// admission, including inside one atomic batch; multi slots can retain both ids.
func TestSingleSequenceAdmission(t *testing.T) {
	for _, mode := range []string{"single", "multi"} {
		t.Run(mode, func(t *testing.T) {
			snapshot, op := basicWrite(t)
			first := firstProposal(op)
			for _, d := range arr(snapshot["domain_schemas"]) {
				if obj(d)["id"] == obj(env(first)["schema"])["id"] {
					obj(obj(d)["cardinality"])["mode"] = mode
				}
			}
			second := copyJSON(first)
			env(second)["id"] = "rec:b"
			authorizeProposal(snapshot, second)
			op["proposals"] = []any{first, second}
			s := stateForTest(t, snapshot)
			if mode == "single" {
				refusalUnchanged(t, s, op, VersionConflict)
				op["proposals"] = []any{first}
				success(t, s, op)
				op["proposals"] = []any{second}
				op["idempotency_key"] = "key:second"
				refusalUnchanged(t, s, op, VersionConflict)
			} else {
				success(t, s, op)
				if len(arr(s.snapshot["records"])) != 2 {
					t.Fatal("multi ids collapsed")
				}
			}
		})
	}
}

// TestRevisionTokens proves availability/withdraw transitions use revision refs
// as subsequent CAS tokens, while challenges do not advance the target head.
func TestRevisionTokens(t *testing.T) {
	snapshot, _ := writeFixture(t, "S30")
	_, ops := writeFixture(t, "S17")
	base := obj(ops[0])
	source := map[string]any{"id": "rec:grounds", "version": int64(1)}
	requests := []map[string]any{}
	for i, id := range []string{"rec:availability1", "rec:availability2", "rec:withdraw"} {
		op := copyJSON(base).(map[string]any)
		op["replacement"] = nil
		op["idempotency_key"] = id
		r := op["revision"]
		env(r)["id"] = id
		b := body(r)
		b["relation"] = "availability"
		b["availability"] = "unavailable"
		b["target"] = source
		b["replacement"] = nil
		if i == 2 {
			b["relation"] = "withdraw"
			b["availability"] = nil
		}
		op["expected_version"] = source
		if i > 0 {
			op["expected_version"] = ref(requests[i-1]["revision"])
		}
		authorizeProposal(snapshot, r)
		requests = append(requests, op)
	}
	s := stateForTest(t, snapshot)
	for _, op := range requests {
		success(t, s, op)
	}
	if s.runtime()["memory_cut"] != int64(103) {
		t.Fatal("non-record cut")
	}
	stateForTest(t, s.Snapshot())
	old := copyJSON(requests[1]).(map[string]any)
	old["idempotency_key"] = "new-key"
	refusalUnchanged(t, s, old, VersionConflict)
	snapshot, ops = writeFixture(t, "S19")
	s = stateForTest(t, snapshot)
	index := recordIndex(arr(snapshot["records"]))
	target := index[refKey(body(obj(ops[0])["revision"])["target"])]
	before := s.head(target, arr(snapshot["records"]), obj(obj(ops[0])["context"]))
	success(t, s, obj(ops[0]))
	after := s.head(target, arr(s.snapshot["records"]), obj(obj(ops[0])["context"]))
	if !reflect.DeepEqual(before, after) {
		t.Fatal("challenge replaced head")
	}
}

// TestCanonicalReceiptScope proves protected event issuer governs order even
// when source envelopes are foreign; noncanonical or unreadable receipts cannot
// authorize replacement, and multiple maxima are a CAS conflict.
func TestCanonicalReceiptScope(t *testing.T) {
	snapshot, ops := writeFixture(t, "B01")
	op := obj(ops[6])
	s := stateForTest(t, snapshot)
	receipt := body(op["replacement"])["authority_receipt"]
	source := recordIndex(arr(s.snapshot["records"]))[refKey(receipt)]
	body(source)["provenance"] = "imported"
	env(source)["issuer"] = "carrier:foreign"
	env(source)["submitter"] = "carrier:foreign"
	obj(env(source)["perspective"])["principal"] = "carrier:foreign"
	success(t, s, op)
	for _, mutate := range []func(*State){func(s *State) { s.event(receipt)["canonical"] = false }, func(s *State) {
		for _, g := range arr(s.policy()["grants"]) {
			obj(g)["metadata"] = false
		}
	}, func(s *State) { s.event(receipt)["issuer"] = "foreign" }} {
		s = stateForTest(t, snapshot)
		mutate(s)
		refusalUnchanged(t, s, op, AuthorityReceiptRequired)
	}
	snapshot, ops = writeFixture(t, "S39")
	s = stateForTest(t, snapshot)
	success(t, s, obj(ops[4]))
	refusalUnchanged(t, s, obj(ops[5]), VersionConflict)
}

// TestHistoricalTargetCannotBorrowToken proves a correct current token cannot
// authorize replacing an older target, even when its replacement id exists.
func TestHistoricalTargetCannotBorrowToken(t *testing.T) {
	snapshot, ops := writeFixture(t, "S17")
	op := obj(ops[0])
	s := stateForTest(t, snapshot)
	success(t, s, op)
	old := copyJSON(op).(map[string]any)
	old["idempotency_key"] = "new-key"
	env(old["revision"])["id"] = "rec:stale-new"
	old["expected_version"] = body(old["revision"])["replacement"]
	authorizeProposal(s.snapshot, old["revision"])
	refusalUnchanged(t, s, old, VersionConflict)
}

// TestRegisteredRuleWithdrawal proves removing an active sufficient-support rule
// dirties its conclusion and retains that exact revision cause across reload.
func TestRegisteredRuleWithdrawal(t *testing.T) {
	snapshot, admit := goodRuleWrite(t)
	_, ops := writeFixture(t, "S17")
	withdraw := obj(ops[0])
	withdraw["replacement"] = nil
	env(withdraw["revision"])["id"] = "rec:withdraw-rule"
	b := body(withdraw["revision"])
	b["relation"] = "withdraw"
	b["replacement"] = nil
	b["target"] = ref(firstProposal(admit))
	withdraw["expected_version"] = b["target"]
	authorizeProposal(snapshot, withdraw["revision"])
	s := stateForTest(t, snapshot)
	success(t, s, admit)
	success(t, s, withdraw)
	target := obj(body(firstProposal(admit))["target"])["assertion"]
	if !contains(s.runtime()["dirty"], target) || !contains(s.runtime()["dirty_causes"], map[string]any{"assertion": target, "revision": ref(withdraw["revision"])}) {
		t.Fatal("rule withdrawal did not invalidate its conclusion")
	}
	stateForTest(t, s.Snapshot())
}
