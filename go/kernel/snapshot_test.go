package kernel

import (
	"reflect"
	"testing"
)

// TestSnapshotInvariants proves construction refuses malformed, dangling,
// unattributed, cyclic and inconsistent admitted states, alongside valid
// controls. Future protected facts alone do not count as admitted records.
func TestSnapshotInvariants(t *testing.T) {
	for _, tc := range []struct {
		name, id string
		code     RefusalCode
		mutate   func(map[string]any)
	}{
		{"closed state", "S01", InvalidShape, func(s map[string]any) { s["extra"] = true }},
		{"unknown profile", "S01", UnknownProfile, func(s map[string]any) { obj(s["policy"])["profile"] = "unknown" }},
		{"duplicate immutable version", "S01", DuplicateRecord, func(s map[string]any) { s["records"] = append(arr(s["records"]), copyJSON(arr(s["records"])[0])) }},
		{"future recorded sequence", "S01", InvalidTime, func(s map[string]any) { obj(env(arr(s["records"])[0])["recorded"])["sequence"] = int64(101) }},
		{"missing atomic cut", "S01", InvalidTime, func(s map[string]any) { obj(s["runtime"])["committed_cuts"] = []any{} }},
		{"missing integration fact", "S01", InvalidReference, func(s map[string]any) { obj(s["policy"])["lineage_facts"] = []any{} }},
		{"duplicate integration fact", "S01", InvalidReference, func(s map[string]any) {
			p := obj(s["policy"])
			p["lineage_facts"] = append(arr(p["lineage_facts"]), copyJSON(arr(p["lineage_facts"])[0]))
		}},
		{"future fact cannot resolve input", "S01", InvalidReference, func(s map[string]any) {
			p := obj(s["policy"])
			fact := obj(arr(p["lineage_facts"])[0])
			fact["kind"] = "deterministic"
			fact["inputs"] = []any{map[string]any{"id": "not-admitted", "version": int64(1)}}
			env(arr(s["records"])[0])["lineage"] = copyJSON(fact["inputs"])
		}},
		{"unbound self declaration", "P10", InvalidDomainValue, func(s map[string]any) { obj(s["policy"])["subject_principals"] = []any{} }},
		{"unknown authority source", "B01", InvalidReference, func(s map[string]any) {
			obj(arr(obj(s["policy"])["authority_events"])[0])["receipt"] = map[string]any{"id": "missing", "version": int64(1)}
		}},
		{"authority DAG cycle", "B01", Cycle, func(s map[string]any) {
			event := obj(arr(obj(s["policy"])["authority_events"])[0])
			event["predecessors"] = []any{copyJSON(event["receipt"])}
		}},
		{"dirty without cause", "S01", InvalidReference, func(s map[string]any) { obj(s["runtime"])["dirty"] = []any{ref(arr(s["records"])[0])} }},
		{"duplicate domain fields", "S01", InvalidDomainValue, func(s map[string]any) {
			d := obj(arr(s["domain_schemas"])[0])
			d["fields"] = append(arr(d["fields"]), copyJSON(arr(d["fields"])[0]))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			snapshot, _ := writeFixture(t, tc.id)
			stateForTest(t, snapshot)
			tc.mutate(snapshot)
			before := copyJSON(snapshot)
			s, r := NewState(snapshot, packageSchemas(t), mintForTest())
			if s != nil || r == nil || r.Code != tc.code {
				t.Fatal(r, "want", tc.code)
			}
			if !reflect.DeepEqual(snapshot, before) {
				t.Fatal("constructor mutated caller snapshot")
			}
		})
	}
}

// TestSnapshotRoundTrip proves writes persist an admitted complete state,
// including original replay handles and dirty causes, that can be loaded again.
func TestSnapshotRoundTrip(t *testing.T) {
	for _, id := range []string{"B01", "P10", "S17", "P03"} {
		t.Run(id, func(t *testing.T) {
			snapshot, ops := writeFixture(t, id)
			s := stateForTest(t, snapshot)
			index := 0
			if id == "B01" {
				index = 6
			}
			receipt := success(t, s, obj(ops[index]))
			loaded := stateForTest(t, s.Snapshot())
			if !reflect.DeepEqual(loaded.Snapshot(), s.Snapshot()) {
				t.Fatal("round trip")
			}
			if got := success(t, loaded, obj(ops[index])); !reflect.DeepEqual(got, receipt) {
				t.Fatal("reloaded replay")
			}
		})
	}
}

// TestReplayLedgerBindings proves canonical JSON alone cannot authenticate a
// ledger entry for the wrong actor, operation, output refs or recorded stamp.
func TestReplayLedgerBindings(t *testing.T) {
	snapshot, op := basicWrite(t)
	s := stateForTest(t, snapshot)
	success(t, s, op)
	stored := s.Snapshot()
	stateForTest(t, stored)
	for _, mutate := range []func(map[string]any){func(e map[string]any) { e["actor"] = "other" }, func(e map[string]any) { obj(e["receipt"])["operation"] = "revise" }, func(e map[string]any) { obj(e["receipt"])["refs"] = []any{} }, func(e map[string]any) {
		parsed, _ := DecodeJSON([]byte(e["canonical_request"].(string)))
		obj(obj(parsed)["context"])["at"] = "2026-10-17T00:00:00Z"
		e["canonical_request"] = key(parsed)
	}} {
		bad := copyJSON(stored).(map[string]any)
		mutate(obj(arr(obj(bad["runtime"])["idempotency"])[0]))
		state, r := NewState(bad, packageSchemas(t), mintForTest())
		if state != nil || r == nil || r.Code != InvalidReference {
			t.Fatal(r)
		}
	}
}
