package kernel

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// TestCorpusHiddenRecordNoninterference checks every corpus capture and final
// read against each disclosure-denied record's removal, including reference-only
// dependents. Pairs preserve public policy, cuts, availability and captures.
// Removing an independently released/authorized assertion changes authorized
// inputs and is outside NI-1; those dependency cases are counted separately.
func TestCorpusHiddenRecordNoninterference(t *testing.T) {
	files, err := filepath.Glob("../../spec/kernel/vectors/semantic/*.json")
	if err != nil {
		t.Fatal(err)
	}
	pairs, refusals, releasedDependencies := 0, 0, 0
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		v, r := DecodeJSON(data)
		if r != nil {
			t.Fatal(r)
		}
		vector := obj(v)
		s := stateForTest(t, obj(vector["initial_state"]))
		check := func(q map[string]any) {
			index := recordIndex(arr(s.snapshot["records"]))
			var projection map[string]any
			for _, raw := range arr(s.snapshot["projection_rules"]) {
				if refKey(raw) == refKey(q["projection_rule"]) {
					projection = obj(raw)
				}
			}
			for _, hidden := range arr(s.snapshot["records"]) {
				denied := !s.disclosureAllows(hidden, q["audience"], q["purpose"], q["now"], index, map[string]bool{})
				for _, right := range []string{"read", "use"} {
					if !s.grant(q["principal"], env(hidden)["space"], env(hidden)["id"], q["audience"], q["purpose"], right, true) {
						denied = true
					}
				}
				if projection["family"] == "audience_projection" && !s.completeLineage(hidden, index, map[string]bool{}) {
					denied = true
				}
				if !denied {
					continue
				}
				candidate, removed := withoutHidden(s, hidden)
				g := s.newReadGraph(q, projection, map[string]int64{})
				changesAuthorized := false
				for _, record := range arr(s.snapshot["records"]) {
					if removed[refKey(ref(record))] && env(record)["kind"] == "assertion" && g.allowed(record) {
						changesAuthorized = true
					}
				}
				if changesAuthorized {
					releasedDependencies++
					continue
				}
				// Fresh mints avoid collisions with imported successful-write receipts.
				pairState := func(snapshot map[string]any) *State {
					n := 1000000
					x, refusal := NewState(snapshot, s.schemas, func() (string, error) { n++; return fmt.Sprintf("%032x", n), nil })
					if refusal != nil {
						t.Fatalf("%v hidden=%v invalid pair: %v", vector["id"], ref(hidden), refusal)
					}
					x.captures = s.captures
					return x
				}
				a, b := pairState(s.Snapshot()), pairState(candidate)
				compare := func(query map[string]any) {
					left, lr := a.Read(query)
					right, rr := b.Read(query)
					if !reflect.DeepEqual(lr, rr) {
						t.Fatalf("%v hidden=%v refusal changed: %v / %v", vector["id"], ref(hidden), lr, rr)
					}
					if lr != nil {
						refusals++
					} else {
						lc, rc := comparableView(left), comparableView(right)
						lc["changes"], rc["changes"] = left["changes"], right["changes"]
						if !equalJSON(lc, rc) {
							t.Fatalf("%v hidden=%v disclosed removal\nleft=%s\nright=%s", vector["id"], ref(hidden), key(lc), key(rc))
						}
					}
				}
				compare(q)
				bad := copyJSON(q).(map[string]any)
				obj(bad["policy"])["version"] = int64(987654)
				compare(bad)
				pairs++
			}
		}
		for i, raw := range arr(vector["operations"]) {
			op := obj(raw)
			switch op["op"] {
			case "capture":
				check(obj(op["query"]))
				s.Capture(int64(i), obj(op["query"]))
			case "set_availability":
				s.SetAvailability(op)
			case "load":
				s.SeedLoad(op["actor"].(string), op["hidden_work"].(int64))
			default:
				s.Write(op)
			}
		}
		check(obj(vector["query"]))
	}
	if len(files) != 66 || pairs == 0 || refusals < pairs {
		t.Fatal("property did not exercise corpus hidden records and refusals", len(files), pairs, refusals)
	}
	t.Logf("66 vectors; %d hidden-record removal pairs; %d unchanged refusals; %d removals change authorized assertion dependencies (outside NI-1)", pairs, refusals, releasedDependencies)
}

// withoutHidden removes referential dependents to keep both snapshots valid;
// protected metadata referring solely to removed inventory is pruned as well.
func withoutHidden(s *State, hidden any) (map[string]any, map[string]bool) {
	removed := map[string]bool{refKey(ref(hidden)): true}
	var referencesRemoved func(any) bool
	referencesRemoved = func(v any) bool {
		switch x := v.(type) {
		case map[string]any:
			if len(x) == 2 && x["id"] != nil && x["version"] != nil && removed[refKey(x)] {
				return true
			}
			for _, c := range x {
				if referencesRemoved(c) {
					return true
				}
			}
		case []any:
			for _, c := range x {
				if referencesRemoved(c) {
					return true
				}
			}
		}
		return false
	}
	for changed := true; changed; {
		changed = false
		for _, r := range arr(s.snapshot["records"]) {
			k := refKey(ref(r))
			if !removed[k] && (referencesRemoved(r) || referencesRemoved(s.fact(r)["inputs"])) {
				removed[k], changed = true, true
			}
		}
		for _, raw := range arr(s.policy()["authority_events"]) {
			e := obj(raw)
			k := refKey(e["receipt"])
			if !removed[k] && referencesRemoved(e["predecessors"]) {
				removed[k], changed = true, true
			}
		}
	}
	out := s.Snapshot()
	kept := []any{}
	for _, r := range arr(out["records"]) {
		if !removed[refKey(ref(r))] {
			kept = append(kept, r)
		}
	}
	out["records"] = kept
	policy, runtime := obj(out["policy"]), obj(out["runtime"])
	removedCustody := map[string]bool{}
	for _, raw := range arr(runtime["custody"]) {
		if referencesRemoved(raw) {
			removedCustody[obj(raw)["id"].(string)] = true
		}
	}
	prune := func(m map[string]any, field string) {
		kept := []any{}
		for _, raw := range arr(m[field]) {
			if !referencesRemoved(raw) {
				kept = append(kept, raw)
			}
		}
		m[field] = kept
	}
	for _, field := range []string{"coverage", "source_access", "imports", "authority_events"} {
		prune(policy, field)
	}
	for _, field := range []string{"custody", "dirty_causes", "dirty"} {
		prune(runtime, field)
	}
	// A dirty assertion with no surviving cause must no longer be marked dirty.
	kept = []any{}
	for _, v := range arr(runtime["dirty"]) {
		for _, cause := range arr(runtime["dirty_causes"]) {
			if equalJSON(v, obj(cause)["assertion"]) {
				kept = append(kept, v)
				break
			}
		}
	}
	runtime["dirty"] = kept
	kept = []any{}
	for _, raw := range arr(runtime["idempotency"]) {
		entry := obj(raw)
		intent, _ := DecodeJSON([]byte(entry["canonical_request"].(string)))
		missingCustody := false
		for _, id := range arr(obj(entry["receipt"])["custody"]) {
			if removedCustody[id.(string)] {
				missingCustody = true
			}
		}
		if !missingCustody && !referencesRemoved(entry["receipt"]) && !referencesRemoved(intent) {
			kept = append(kept, raw)
		}
	}
	runtime["idempotency"] = kept
	return out, removed
}
