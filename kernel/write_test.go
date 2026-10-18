package kernel

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func writeFixture(t *testing.T, id string) (map[string]any, []any) {
	t.Helper()
	files, e := filepath.Glob("../spec/kernel/vectors/semantic/" + id + "*.json")
	if e != nil || len(files) != 1 {
		t.Fatal(id, e, files)
	}
	b, e := os.ReadFile(files[0])
	if e != nil {
		t.Fatal(e)
	}
	v, r := DecodeJSON(b)
	if r != nil {
		t.Fatal(r)
	}
	m := obj(v)
	return obj(m["initial_state"]), arr(m["operations"])
}
func mintForTest() func() (string, error) {
	n := 0
	return func() (string, error) { n++; return fmt.Sprintf("%032x", n), nil }
}
func stateForTest(t *testing.T, snapshot map[string]any) *State {
	t.Helper()
	s, r := NewState(snapshot, packageSchemas(t), mintForTest())
	if r != nil {
		t.Fatal("snapshot", r)
	}
	return s
}
func success(t *testing.T, s *State, op map[string]any) map[string]any {
	t.Helper()
	receipt, r := s.Write(op)
	if r != nil || receipt == nil || receipt["type"] != "receipt" || !validHandle(receipt["receipt_handle"].(string)) {
		t.Fatal(receipt, r)
	}
	return receipt
}
func refusalUnchanged(t *testing.T, s *State, op map[string]any, code RefusalCode) {
	t.Helper()
	before := s.Snapshot()
	receipt, r := s.Write(op)
	want, _ := NewRefusal(code)
	if receipt != nil || !reflect.DeepEqual(r, want) {
		t.Fatalf("got %v, %v; want %v", receipt, r, want)
	}
	if !reflect.DeepEqual(before, s.Snapshot()) {
		t.Fatal("refusal changed complete state")
	}
}
func basicWrite(t *testing.T) (map[string]any, map[string]any) {
	snapshot, ops := writeFixture(t, "S14")
	return snapshot, obj(ops[0])
}
func goodRuleWrite(t *testing.T) (map[string]any, map[string]any) {
	snapshot, ops := writeFixture(t, "S08")
	op := obj(ops[0])
	op["proposals"] = arr(op["proposals"])[:2]
	return snapshot, op
}
func firstProposal(op map[string]any) any { return arr(op["proposals"])[0] }

// TestWriteRefusalNeighbors proves each emitted write refusal has a specific
// rejection witness, a successful nearby control and full-state atomicity.
func TestWriteRefusalNeighbors(t *testing.T) {
	for _, tc := range []struct {
		name    string
		code    RefusalCode
		prepare func(*testing.T) (map[string]any, map[string]any)
		bad     func(*State, map[string]any)
	}{
		{"JSON duplicate", InvalidJSON, basicWrite, func(s *State, o map[string]any) {
			o["op"] = "admit_raw"
			delete(o, "proposals")
			o["raw_json"] = `{"proposals":[],"proposals":[]}`
		}},
		{"closed shape", InvalidShape, basicWrite, func(s *State, o map[string]any) { env(firstProposal(o))["submitter"] = "forged" }},
		{"schema exact version", UnknownSchema, basicWrite, func(s *State, o map[string]any) { obj(env(firstProposal(o))["schema"])["version"] = int64(999) }},
		{"missing integration fact", InvalidReference, basicWrite, func(s *State, o map[string]any) { s.policy()["lineage_facts"] = []any{} }},
		{"duplicate immutable record", DuplicateRecord, basicWrite, func(s *State, o map[string]any) { success(t, s, o); o["idempotency_key"] = "key:new" }},
		{"content type", InvalidDomainValue, basicWrite, func(s *State, o map[string]any) { obj(arr(body(firstProposal(o))["content"])[0])["value"] = true }},
		{"calendar", InvalidTime, basicWrite, func(s *State, o map[string]any) { env(firstProposal(o))["confirmed_at"] = "2026-02-30T00:00:00Z" }},
		{"support cycle", Cycle, goodRuleWrite, func(s *State, o map[string]any) {
			_, ops := writeFixture(t, "S08")
			o["proposals"] = obj(ops[0])["proposals"]
		}},
		{"cross-space premise", CrossScope, goodRuleWrite, func(s *State, o map[string]any) {
			p := obj(arr(body(firstProposal(o))["premises"])[0])
			v := obj(p["literal"])["assertion"]
			for _, r := range arr(s.snapshot["records"]) {
				if equalJSON(ref(r), v) {
					env(r)["space"] = "space:other"
				}
			}
		}},
		{"representation", RepresentationInvalid, basicWrite, func(s *State, o map[string]any) { env(firstProposal(o))["issuer"] = "principal:other" }},
		{"retention grant", NotAuthorized, basicWrite, func(s *State, o map[string]any) {
			for _, g := range arr(s.policy()["grants"]) {
				rights := []any{}
				for _, r := range arr(obj(g)["rights"]) {
					if r != "retain" {
						rights = append(rights, r)
					}
				}
				obj(g)["rights"] = rights
			}
		}},
		{"explicit review", Quarantined, basicWrite, func(s *State, o map[string]any) { s.policy()["reviews"] = []any{} }},
		{"authority receipt", AuthorityReceiptRequired, func(t *testing.T) (map[string]any, map[string]any) {
			s, o := writeFixture(t, "B01")
			return s, obj(o[6])
		}, func(s *State, o map[string]any) { body(o["replacement"])["authority_receipt"] = nil }},
		{"compare and set", VersionConflict, func(t *testing.T) (map[string]any, map[string]any) {
			s, o := writeFixture(t, "P10")
			return s, obj(o[0])
		}, func(s *State, o map[string]any) { obj(o["expected_version"])["version"] = int64(99) }},
		{"changed intent", IdempotencyConflict, basicWrite, func(s *State, o map[string]any) {
			success(t, s, o)
			obj(arr(body(firstProposal(o))["content"])[0])["value"] = "changed"
		}},
		{"unqualified support", RuleUnqualified, goodRuleWrite, func(s *State, o map[string]any) { body(firstProposal(o))["check"] = nil }},
		{"model check kind", AssessmentKindInvalid, goodRuleWrite, func(s *State, o map[string]any) { body(arr(o["proposals"])[1])["executor"] = "model" }},
		{"record bound", LimitExceeded, basicWrite, func(s *State, o map[string]any) { obj(s.policy()["limits"])["max_records"] = int64(0) }},
		{"erasure fence", ErasureFenced, basicWrite, func(s *State, o map[string]any) { s.runtime()["fences"] = []any{ref(firstProposal(o))} }},
		{"stale writer", StaleGeneration, basicWrite, func(s *State, o map[string]any) { s.runtime()["erasure_generation"] = int64(1) }},
		{"handle source", Unavailable, basicWrite, func(s *State, o map[string]any) {
			s.mint = func() (string, error) { return "", errors.New("entropy unavailable") }
		}},
		{"unsupported read", UnsupportedOperation, basicWrite, func(s *State, o map[string]any) { o["op"] = "recall" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			snapshot, op := tc.prepare(t)
			success(t, stateForTest(t, snapshot), op)
			s := stateForTest(t, snapshot)
			tc.bad(s, op)
			refusalUnchanged(t, s, op, tc.code)
		})
	}
}

// TestFirstViolationOrder proves four K-API-2 class pairs prefer the earlier
// violation across the whole batch, with each later violation checked alone.
func TestFirstViolationOrder(t *testing.T) {
	for _, tc := range []struct {
		name          string
		early, late   RefusalCode
		first, second func(*State, map[string]any)
	}{
		{"shape before rights", InvalidShape, NotAuthorized, func(s *State, o map[string]any) { o["extra"] = true }, func(s *State, o map[string]any) { s.policy()["grants"] = []any{} }},
		{"rights before review", NotAuthorized, Quarantined, func(s *State, o map[string]any) { s.policy()["grants"] = []any{} }, func(s *State, o map[string]any) { s.policy()["reviews"] = []any{} }},
		{"review before generation", Quarantined, StaleGeneration, func(s *State, o map[string]any) { s.policy()["reviews"] = []any{} }, func(s *State, o map[string]any) { o["expected_generation"] = int64(1) }},
		{"generation before content", StaleGeneration, InvalidDomainValue, func(s *State, o map[string]any) { o["expected_generation"] = int64(1) }, func(s *State, o map[string]any) { body(firstProposal(o))["slot"] = "wrong" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			snapshot, op := basicWrite(t)
			success(t, stateForTest(t, snapshot), op)
			s := stateForTest(t, snapshot)
			tc.second(s, op)
			refusalUnchanged(t, s, op, tc.late)
			snapshot, op = basicWrite(t)
			s = stateForTest(t, snapshot)
			tc.first(s, op)
			tc.second(s, op)
			refusalUnchanged(t, s, op, tc.early)
		})
	}
	// The later record's review failure outranks the first record's content error.
	snapshot, ops := writeFixture(t, "P03")
	op := obj(ops[0])
	s := stateForTest(t, snapshot)
	body(firstProposal(op))["slot"] = "wrong"
	second := arr(op["proposals"])[1]
	reviews := []any{}
	for _, r := range arr(s.policy()["reviews"]) {
		if !equalJSON(obj(r)["record"], ref(second)) {
			reviews = append(reviews, r)
		}
	}
	s.policy()["reviews"] = reviews
	refusalUnchanged(t, s, op, Quarantined)
}

// TestBatchCommitAndReplay proves sequence assignment, one atomic readable cut,
// dirty marking, input/output isolation and exact replay after a head advance.
func TestBatchCommitAndReplay(t *testing.T) {
	snapshot, ops := writeFixture(t, "B01")
	s := stateForTest(t, snapshot)
	first := success(t, s, obj(ops[6]))
	after := s.Snapshot()
	last := arr(after["records"])
	if env(last[len(last)-2])["id"] != "rec:d" || obj(env(last[len(last)-2])["recorded"])["sequence"] != int64(101) || obj(env(last[len(last)-1])["recorded"])["sequence"] != int64(102) {
		t.Fatal("transaction order", last)
	}
	if contains(obj(after["runtime"])["committed_cuts"], int64(101)) || !contains(obj(after["runtime"])["committed_cuts"], int64(102)) {
		t.Fatal("partial cut exposed")
	}
	success(t, s, obj(ops[8]))
	before := s.Snapshot()
	replay := obj(copyJSON(ops[6]))
	obj(replay["context"])["at"] = "2026-10-18T00:00:00Z"
	got := success(t, s, replay)
	if !reflect.DeepEqual(first, got) || !reflect.DeepEqual(before, s.Snapshot()) {
		t.Fatal("replay changed receipt or state")
	}
	first["receipt_handle"] = "tamper"
	env(arr(after["records"])[0])["id"] = "tamper"
	snapshot["records"] = []any{}
	if !reflect.DeepEqual(before, s.Snapshot()) {
		t.Fatal("alias escaped")
	}
	snapshot, ops = writeFixture(t, "S17")
	s = stateForTest(t, snapshot)
	success(t, s, obj(ops[0]))
	if len(arr(s.runtime()["dirty"])) == 0 || len(arr(s.runtime()["dirty_causes"])) == 0 {
		t.Fatal("registered dependents not dirty")
	}
}

// TestRepresentativeRace proves exactly one representative commits from the
// same CAS token; retrying the loser leaves every state field unchanged.
func TestRepresentativeRace(t *testing.T) {
	snapshot, ops := writeFixture(t, "P10")
	s := stateForTest(t, snapshot)
	var wg sync.WaitGroup
	start := make(chan struct{})
	results := make(chan int, 2)
	for _, i := range []int{0, 2} {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, r := s.Write(obj(ops[i]))
			if r == nil {
				results <- i
			} else if r.Code == VersionConflict {
				results <- -i - 1
			} else {
				t.Errorf("race: %v", r)
			}
		}(i)
	}
	close(start)
	wg.Wait()
	close(results)
	wins, losses, loser := 0, 0, 0
	for r := range results {
		if r >= 0 {
			wins++
		} else {
			losses++
			loser = -r - 1
		}
	}
	if wins != 1 || losses != 1 {
		t.Fatal(wins, losses)
	}
	if len(arr(s.snapshot["records"])) != len(arr(snapshot["records"]))+2 || len(arr(s.runtime()["idempotency"])) != 1 || s.runtime()["memory_cut"] != int64(102) {
		t.Fatal("loser committed")
	}
	refusalUnchanged(t, s, obj(ops[loser]), VersionConflict)
}

// TestRetentionReplay proves denied writes create no entry and current retain
// revocation or exact deadline overrides an existing successful replay.
func TestRetentionReplay(t *testing.T) {
	snapshot, op := basicWrite(t)
	s := stateForTest(t, snapshot)
	grants := copyJSON(s.policy()["grants"])
	s.policy()["grants"] = []any{}
	refusalUnchanged(t, s, op, NotAuthorized)
	s.policy()["grants"] = grants
	receipt := success(t, s, op)
	ctx := obj(op["context"])
	retention := obj(ctx["retention_context"])
	s.runtime()["revocations"] = []any{map[string]any{"principal": ctx["actor"], "audience": retention["audience"], "purpose": retention["purpose"], "right": "retain"}}
	refusalUnchanged(t, s, op, NotAuthorized)
	if obj(obj(arr(s.runtime()["idempotency"])[0])["receipt"])["receipt_handle"] != receipt["receipt_handle"] {
		t.Fatal("receipt overwritten")
	}
	snapshot, ops := writeFixture(t, "P11")
	s = stateForTest(t, snapshot)
	success(t, s, obj(ops[16]))
	success(t, s, obj(ops[17]))
	refusalUnchanged(t, s, obj(ops[18]), NotAuthorized)
	refusalUnchanged(t, s, obj(ops[23]), NotAuthorized)
}

// TestIssuerLocalOrder proves foreign bypasses cannot order H, intermediate H
// events need no attached assertion, and foreign-only edits preserve H's order.
func TestIssuerLocalOrder(t *testing.T) {
	snapshot, _ := writeFixture(t, "S01")
	r := func(id string) any { return map[string]any{"id": "rec:event-" + id, "version": int64(1)} }
	a, b, m, f := r("a"), r("b"), r("middle"), r("foreign")
	event := func(receipt, issuer any, predecessors ...any) any {
		if predecessors == nil {
			predecessors = []any{}
		}
		return map[string]any{"receipt": receipt, "issuer": issuer, "predecessors": predecessors, "canonical": true}
	}
	receipts, _ := writeFixture(t, "B01")
	var source any
	for _, record := range arr(receipts["records"]) {
		if env(record)["kind"] == "source" {
			source = record
			break
		}
	}
	for i, receipt := range []any{a, b, m, f} {
		record := copyJSON(source)
		env(record)["id"] = obj(receipt)["id"]
		obj(env(record)["recorded"])["sequence"] = int64(3 + i)
		snapshot["records"] = append(arr(snapshot["records"]), record)
		authorizeProposal(snapshot, record)
	}
	obj(snapshot["policy"])["authority_events"] = []any{event(a, "H"), event(b, "H", f), event(f, "F", a), event(m, "H", a)}
	s := stateForTest(t, snapshot)
	if s.precedes("H", a, b) {
		t.Fatal("foreign bypass contracted")
	}
	s.event(f)["predecessors"] = []any{}
	stateForTest(t, s.Snapshot())
	if s.precedes("H", a, b) {
		t.Fatal("foreign edit introduced order")
	}
	s.event(f)["predecessors"] = []any{a}
	s.event(b)["predecessors"] = []any{f, m}
	stateForTest(t, s.Snapshot())
	if !s.precedes("H", a, b) || s.precedes("H", b, a) || s.precedes("H", a, a) {
		t.Fatal("strict all-H order")
	}
	s.event(f)["predecessors"] = []any{}
	stateForTest(t, s.Snapshot())
	if !s.precedes("H", a, b) {
		t.Fatal("foreign graph changed H order")
	}
}

// TestAuthoritySuccessionAtomicity proves equal, prior and incomparable receipts
// all refuse non-retryably and leave full state intact; a later receipt succeeds.
func TestAuthoritySuccessionAtomicity(t *testing.T) {
	for _, mode := range []string{"equal", "prior", "incomparable"} {
		t.Run(mode, func(t *testing.T) {
			snapshot, ops := writeFixture(t, "B01")
			op := obj(ops[6])
			success(t, stateForTest(t, snapshot), op)
			s := stateForTest(t, snapshot)
			target := body(recordIndex(arr(s.snapshot["records"]))[refKey(body(op["revision"])["target"])])["authority_receipt"]
			next := body(op["replacement"])["authority_receipt"]
			switch mode {
			case "equal":
				body(op["replacement"])["authority_receipt"] = target
				body(op["revision"])["authority_receipt"] = target
			case "prior":
				for _, v := range arr(s.policy()["authority_events"]) {
					e := obj(v)
					if equalJSON(e["receipt"], target) {
						e["predecessors"] = []any{next}
					} else if equalJSON(e["receipt"], next) {
						e["predecessors"] = []any{}
					}
				}
			case "incomparable":
				s.event(next)["predecessors"] = []any{}
			}
			refusalUnchanged(t, s, op, AuthorityReceiptRequired)
		})
	}
}

// TestUTCSeconds proves real Gregorian dates, UTC-only seconds and half-open
// interval endpoints are enforced without consulting a wall clock.
func TestUTCSeconds(t *testing.T) {
	for _, v := range []string{"2024-02-29T23:59:59Z", "2000-02-29T00:00:00Z"} {
		if !validStamp(v) {
			t.Fatal(v)
		}
	}
	for _, v := range []string{"1900-02-29T00:00:00Z", "2026-02-29T00:00:00Z", "2026-01-01T00:00:60Z", "2026-01-01T00:00:00+00:00", "0000-01-01T00:00:00Z"} {
		if validStamp(v) {
			t.Fatal(v)
		}
	}
	snapshot, op := basicWrite(t)
	s := stateForTest(t, snapshot)
	valid := obj(env(firstProposal(op))["valid"])
	valid["to"] = valid["from"]
	refusalUnchanged(t, s, op, InvalidTime)
	valid["to"] = nil
	success(t, s, op)
}

// TestRawIntake proves the raw variant accepts only its proposals object and
// shares authenticated stamping and idempotency semantics with parsed admission.
func TestRawIntake(t *testing.T) {
	snapshot, op := basicWrite(t)
	raw := copyJSON(op).(map[string]any)
	encoded, _ := CanonicalJSON(map[string]any{"proposals": op["proposals"]})
	raw["op"] = "admit_raw"
	delete(raw, "proposals")
	raw["raw_json"] = string(encoded)
	s := stateForTest(t, snapshot)
	r := success(t, s, raw)
	if !reflect.DeepEqual(r, success(t, s, op)) {
		t.Fatal("raw and parsed intent differ")
	}
	raw["raw_json"] = `{"proposals":[],"extra":1}`
	refusalUnchanged(t, s, raw, InvalidShape)
}

// TestBoundsAndMintFailures proves fan-in and byte bounds plus malformed or
// repeated adapter handles cannot partially commit; valid bounds remain usable.
func TestBoundsAndMintFailures(t *testing.T) {
	for _, limit := range []string{"max_fan_in", "max_payload_bytes"} {
		snapshot, op := goodRuleWrite(t)
		s := stateForTest(t, snapshot)
		success(t, stateForTest(t, snapshot), op)
		obj(s.policy()["limits"])[limit] = int64(0)
		refusalUnchanged(t, s, op, LimitExceeded)
	}
	snapshot, op := basicWrite(t)
	s := stateForTest(t, snapshot)
	s.mint = func() (string, error) { return "short", nil }
	refusalUnchanged(t, s, op, Unavailable)
	s.mint = nil
	refusalUnchanged(t, s, op, Unavailable)
	s.mint = func() (string, error) { return strings.Repeat("a", 32), nil }
	success(t, s, op)
	second := copyJSON(op).(map[string]any)
	second["idempotency_key"] = "key:other"
	env(firstProposal(second))["id"] = "rec:other"
	authorizeProposal(s.snapshot, firstProposal(second))
	refusalUnchanged(t, s, second, Unavailable)
}

// TestQuarantineReviewDominates proves an allow fact cannot hide a quarantine
// review by array order, while an all-allow review set remains a positive control.
func TestQuarantineReviewDominates(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		snapshot, op := basicWrite(t)
		s := stateForTest(t, snapshot)
		success(t, stateForTest(t, snapshot), op)
		reviews := arr(s.policy()["reviews"])
		reviews = append(reviews, map[string]any{"record": ref(firstProposal(op)), "reviewer": "reviewer:second", "result": "quarantine"})
		if reverse {
			for i, j := 0, len(reviews)-1; i < j; i, j = i+1, j-1 {
				reviews[i], reviews[j] = reviews[j], reviews[i]
			}
		}
		s.policy()["reviews"] = reviews
		refusalUnchanged(t, s, op, Quarantined)
	}
}

// TestMintedReceiptAndCounterBound proves the largest readable cut cannot spill
// outside K-JSON-1's safe-integer range or advance after a refused transaction.
func TestMintedReceiptAndCounterBound(t *testing.T) {
	snapshot, op := basicWrite(t)
	s := stateForTest(t, snapshot)
	success(t, stateForTest(t, snapshot), op)
	s.runtime()["memory_cut"] = maxJSONInteger
	s.runtime()["committed_cuts"] = []any{maxJSONInteger}
	refusalUnchanged(t, s, op, LimitExceeded)
}

// TestLoadStimulus proves only the owner may seed hidden work, the seed changes
// no record/cut, and denied or malformed stimuli preserve the complete snapshot.
func TestLoadStimulus(t *testing.T) {
	snapshot, _ := basicWrite(t)
	s := stateForTest(t, snapshot)
	before := s.Snapshot()
	r, f := s.SeedLoad(s.policy()["owner"].(string), 9000)
	if f != nil || r["outcome"] != "proceeded" || !validHandle(r["receipt_handle"].(string)) {
		t.Fatal(r, f)
	}
	after := s.Snapshot()
	obj(before["runtime"])["hidden_work"] = int64(9000)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("load changed semantic state")
	}
	for _, tc := range []struct {
		actor string
		work  int64
		code  RefusalCode
	}{{"other", 0, NotAuthorized}, {s.policy()["owner"].(string), -1, InvalidShape}} {
		r, f = s.SeedLoad(tc.actor, tc.work)
		if r != nil || f == nil || f.Code != tc.code || !reflect.DeepEqual(after, s.Snapshot()) {
			t.Fatal(r, f)
		}
	}
}

// TestFirstFieldViolation proves body field order selects a check-kind failure
// before an invalid rule-pin version; fixing both yields a valid admission.
func TestFirstFieldViolation(t *testing.T) {
	snapshot, op := goodRuleWrite(t)
	s := stateForTest(t, snapshot)
	success(t, s, op)
	assessment := copyJSON(arr(op["proposals"])[1])
	env(assessment)["id"] = "cert:new"
	authorizeProposal(s.snapshot, assessment)
	next := copyJSON(op).(map[string]any)
	next["proposals"] = []any{assessment}
	next["idempotency_key"] = "key:new-cert"
	control := stateForTest(t, s.Snapshot())
	control.mint = func() (string, error) { return strings.Repeat("b", 32), nil }
	success(t, control, next)
	body(assessment)["executor"] = "model"
	obj(obj(body(assessment)["pins"])["rule"])["version"] = int64(0)
	refusalUnchanged(t, s, next, AssessmentKindInvalid)
	body(assessment)["executor"] = "deterministic"
	refusalUnchanged(t, s, next, InvalidDomainValue)
	obj(obj(body(assessment)["pins"])["rule"])["version"] = int64(1)
	success(t, s, next)
}
