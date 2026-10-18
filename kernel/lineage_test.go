package kernel

import (
	"reflect"
	"testing"
)

// TestKnownLineageAndBatchOrder proves forward batch inputs resolve without
// array-order dependence, taint is transitive, incomplete known inputs remain
// mandatory, and a future fact never resolves an absent input record.
func TestKnownLineageAndBatchOrder(t *testing.T) {
	snapshot, ops := writeFixture(t, "P13")
	op := obj(ops[2])
	s := stateForTest(t, snapshot)
	success(t, s, op)
	original := s.Snapshot()
	snapshot, ops = writeFixture(t, "P13")
	op = obj(ops[2])
	batch := arr(op["proposals"])
	for i, j := 0, len(batch)-1; i < j; i, j = i+1, j-1 {
		batch[i], batch[j] = batch[j], batch[i]
	}
	s = stateForTest(t, snapshot)
	success(t, s, op)
	a, b := recordIndex(arr(original["records"])), recordIndex(arr(s.Snapshot()["records"]))
	for k, r := range a {
		if !reflect.DeepEqual(env(r)["lineage"], env(b[k])["lineage"]) || !reflect.DeepEqual(env(r)["disclosure"], env(b[k])["disclosure"]) {
			t.Fatal("batch order changed lineage/taint", k)
		}
	}
	for _, id := range []string{"rec:model-tainted", "rec:model-stage"} {
		r := b[refKey(map[string]any{"id": id, "version": int64(1)})]
		if contains(obj(env(r)["disclosure"])["audiences"], "aud:public") {
			t.Fatal("input taint lost", id)
		}
	}
	unknown := b[refKey(map[string]any{"id": "rec:model-unknown", "version": int64(1)})]
	if env(unknown)["lineage"] != "unknown" {
		t.Fatal("incomplete fact upgraded")
	}
	snapshot, ops = writeFixture(t, "P13")
	s = stateForTest(t, snapshot)
	refusalUnchanged(t, s, obj(ops[0]), NotAuthorized)
	refusalUnchanged(t, s, obj(ops[1]), InvalidReference)
	snapshot, ops = writeFixture(t, "P11")
	s = stateForTest(t, snapshot)
	refusalUnchanged(t, s, obj(ops[21]), NotAuthorized)
	refusalUnchanged(t, s, obj(ops[22]), NotAuthorized)
	success(t, s, obj(ops[27]))
}

// TestInputFenceAndRestoreGate proves fences survive incomplete lineage and
// restore blocks writes, with valid controls and no speculative state mutation.
func TestInputFenceAndRestoreGate(t *testing.T) {
	snapshot, ops := writeFixture(t, "P13")
	op := obj(ops[2])
	success(t, stateForTest(t, snapshot), op)
	s := stateForTest(t, snapshot)
	unknown := arr(op["proposals"])[0]
	for _, r := range arr(op["proposals"]) {
		if s.fact(r)["complete"] == false {
			unknown = r
			break
		}
	}
	inputs := arr(s.fact(unknown)["inputs"])
	if len(inputs) == 0 {
		t.Fatal("fixture must include known lower bound")
	}
	op["proposals"] = []any{unknown}
	s.runtime()["fences"] = []any{inputs[0]}
	refusalUnchanged(t, s, op, ErasureFenced)
	snapshot, op = basicWrite(t)
	s = stateForTest(t, snapshot)
	obj(s.runtime()["restore"])["status"] = "fenced"
	refusalUnchanged(t, s, op, ErasureFenced)
}

// TestAttributionAndClasses proves representation changes submitter only,
// own declarations require trusted subject binding, and model outputs cannot
// claim a non-model admission class.
func TestAttributionAndClasses(t *testing.T) {
	snapshot, ops := writeFixture(t, "P10")
	op := obj(ops[0])
	s := stateForTest(t, snapshot)
	success(t, s, op)
	for _, r := range arr(s.Snapshot()["records"])[len(arr(snapshot["records"])):] {
		e := env(r)
		if e["issuer"] != "subj:h1" || e["subject"] != "subj:h1" || e["submitter"] != "principal:rep1" || obj(e["perspective"])["principal"] != "subj:h1" || obj(e["representation_ref"])["checked"] != true {
			t.Fatal("attribution coerced", e)
		}
	}
	snapshot, ops = writeFixture(t, "P02")
	s = stateForTest(t, snapshot)
	refusalUnchanged(t, s, obj(ops[0]), RepresentationInvalid)
	refusalUnchanged(t, s, obj(ops[1]), InvalidDomainValue)
	success(t, s, obj(ops[2]))
	snapshot, ops = writeFixture(t, "P13")
	op = obj(ops[2])
	s = stateForTest(t, snapshot)
	obj(op["context"])["admission_class"] = "machine_observation"
	refusalUnchanged(t, s, op, InvalidDomainValue)
}
