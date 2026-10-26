package kernel

import (
	"reflect"
	"testing"
)

func auxiliaryRevision(t *testing.T) (map[string]any, map[string]any) {
	t.Helper()
	snapshot, ops := writeFixture(t, "S17")
	op := obj(ops[0])
	sourceState, _ := writeFixture(t, "S30")
	var source any
	for _, r := range arr(sourceState["records"]) {
		if env(r)["kind"] == "source" {
			source = copyJSON(r)
			break
		}
	}
	if source == nil {
		t.Fatal("missing source control")
	}
	env(source)["id"] = "rec:v2:source"
	for _, k := range []string{"submitter", "recorded", "admission_class"} {
		delete(env(source), k)
	}
	body(source)["excerpt"] = "replacement observation"
	body(source)["retention_admission"] = map[string]any{"id": "retention:v2", "version": int64(1)}
	e := copyJSON(env(op["revision"])).(map[string]any)
	e["id"], e["kind"], e["schema"] = "rec:v2:basis", "justification", nil
	basis := map[string]any{"envelope": e, "body": map[string]any{"target": map[string]any{"assertion": ref(op["replacement"]), "polarity": "support"}, "premises": []any{map[string]any{"kind": "source", "source": ref(source)}}, "rule": map[string]any{"id": "rule:documentary-citation", "version": int64(1)}, "rule_kind": "declared_rationale", "role": "documentary_basis", "check": nil}}
	op["auxiliaries"] = []any{source, basis}
	authorizeProposal(snapshot, source)
	authorizeProposal(snapshot, basis)
	return snapshot, op
}

// Atomic revision auxiliaries share admission, receipt, sequence and replay;
// every refused neighbor preserves the complete snapshot, including replay state.
func TestRevisionAuxiliaries(t *testing.T) {
	snapshot, op := auxiliaryRevision(t)
	s := stateForTest(t, snapshot)
	receipt := success(t, s, op)
	if len(arr(receipt["refs"])) != 4 || s.runtime()["memory_cut"] != int64(104) {
		t.Fatal(receipt, s.runtime())
	}
	before := s.Snapshot()
	if !reflect.DeepEqual(receipt, success(t, s, op)) || !reflect.DeepEqual(before, s.Snapshot()) {
		t.Fatal("replay changed receipt/state")
	}
	stateForTest(t, s.Snapshot())
	for _, tc := range []struct {
		name   string
		mutate func(map[string]any, map[string]any)
		code   RefusalCode
	}{
		{"empty", func(_, o map[string]any) { o["auxiliaries"] = []any{} }, InvalidShape},
		{"null", func(_, o map[string]any) { o["auxiliaries"] = nil }, InvalidShape},
		{"too many", func(_, o map[string]any) { o["auxiliaries"] = append(arr(o["auxiliaries"]), make([]any, 7)...) }, InvalidShape},
		{"assertion kind", func(_, o map[string]any) { o["auxiliaries"] = []any{copyJSON(o["replacement"])} }, InvalidShape},
		{"revision kind", func(_, o map[string]any) { o["auxiliaries"] = []any{copyJSON(o["revision"])} }, InvalidShape},
		{"noninitial version", func(_, o map[string]any) { env(arr(o["auxiliaries"])[0])["version"] = int64(2) }, InvalidShape},
		{"duplicate id", func(_, o map[string]any) { env(arr(o["auxiliaries"])[1])["id"] = env(arr(o["auxiliaries"])[0])["id"] }, InvalidShape},
		{"replacement id", func(_, o map[string]any) { env(arr(o["auxiliaries"])[0])["id"] = env(o["replacement"])["id"] }, InvalidShape},
		{"revision id", func(_, o map[string]any) { env(arr(o["auxiliaries"])[0])["id"] = env(o["revision"])["id"] }, InvalidShape},
		{"wrong target", func(_, o map[string]any) {
			obj(body(arr(o["auxiliaries"])[1])["target"])["assertion"] = body(o["revision"])["target"]
		}, InvalidShape},
		{"unreferenced source", func(_, o map[string]any) { o["auxiliaries"] = arr(o["auxiliaries"])[:1] }, InvalidShape},
		{"withdraw", func(_, o map[string]any) {
			body(o["revision"])["relation"] = "withdraw"
			body(o["revision"])["replacement"] = nil
			o["replacement"] = nil
		}, InvalidShape},
		{"challenge", func(_, o map[string]any) {
			body(o["revision"])["relation"] = "challenge"
			body(o["revision"])["replacement"] = nil
			o["replacement"] = nil
		}, InvalidShape},
		{"existing id", func(s, o map[string]any) {
			r := copyJSON(arr(o["auxiliaries"])[0])
			env(r)["version"] = int64(2)
			env(r)["submitter"] = obj(o["context"])["actor"]
			env(r)["admission_class"] = "machine_observation"
			env(r)["recorded"] = map[string]any{"at": obj(o["context"])["at"], "sequence": int64(99)}
			s["records"] = append(arr(s["records"]), r)
			authorizeProposal(s, r)
		}, InvalidShape},
		{"stale CAS", func(_, o map[string]any) { obj(o["expected_version"])["version"] = int64(99) }, VersionConflict},
		{"quarantine", func(s, o map[string]any) {
			body(arr(o["auxiliaries"])[0])["excerpt"] = "scanner witness"
			for _, v := range arr(obj(s["policy"])["reviews"]) {
				if equalJSON(obj(v)["record"], ref(arr(o["auxiliaries"])[0])) {
					obj(v)["result"] = "quarantine"
				}
			}
		}, Quarantined},
		{"forged issuer", func(_, o map[string]any) { env(arr(o["auxiliaries"])[0])["issuer"] = "foreign:issuer" }, RepresentationInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			snapshot, op := auxiliaryRevision(t)
			tc.mutate(snapshot, op)
			refusalUnchanged(t, stateForTest(t, snapshot), op, tc.code)
		})
	}
}

// Both replacement relations accept a basis citing an already admitted source;
// an absent extension preserves the old two-record batch and receipt shape.
func TestRevisionAuxiliaryNeighbors(t *testing.T) {
	for _, relation := range []string{"replace", "correct"} {
		t.Run(relation, func(t *testing.T) {
			snapshot, op := auxiliaryRevision(t)
			body(op["revision"])["relation"] = relation
			success(t, stateForTest(t, snapshot), op)
			source := copyJSON(arr(op["auxiliaries"])[0])
			e := env(source)
			e["submitter"] = obj(op["context"])["actor"]
			e["admission_class"] = "machine_observation"
			e["recorded"] = map[string]any{"at": obj(op["context"])["at"], "sequence": int64(99)}
			snapshot["records"] = append(arr(snapshot["records"]), source)
			op["auxiliaries"] = arr(op["auxiliaries"])[1:]
			success(t, stateForTest(t, snapshot), op)
			delete(op, "auxiliaries")
			receipt := success(t, stateForTest(t, snapshot), op)
			if len(arr(receipt["refs"])) != 2 {
				t.Fatal(receipt)
			}
		})
	}
}
