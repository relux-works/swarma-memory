package conformance

import (
	"github.com/relux-works/swarma-memory/kernel"
	"strings"
	"testing"
)

func findVector(t *testing.T, id string) Vector {
	t.Helper()
	for _, v := range suite(t) {
		if v.ID() == id {
			return v
		}
	}
	t.Fatal(id)
	return Vector{}
}
func partByID(t *testing.T, parts []PartVerdict, id string) PartVerdict {
	t.Helper()
	for _, p := range parts {
		if p.ID == id {
			return p
		}
	}
	t.Fatal(id)
	return PartVerdict{}
}

// TestPartControls proves operation measurement rejects changed codes, types,
// extra fields, invalid handles and broken replay equality, while an unrelated
// unsupported read does not erase a valid write result's evidence.
func TestPartControls(t *testing.T) {
	v := findVector(t, "S14")
	baseline := oracle(v)
	for _, p := range CompareParts(v, baseline) {
		if !p.Pass {
			t.Fatal(p)
		}
	}
	for _, tc := range []struct {
		name   string
		mutate func(Report)
	}{
		{"extra receipt field", func(r Report) { r["operation_results"].([]any)[0].(map[string]any)["sequence"] = int64(101) }},
		{"invalid handle", func(r Report) { r["operation_results"].([]any)[0].(map[string]any)["receipt_handle"] = "@h1" }},
		{"broken replay", func(r Report) {
			r["operation_results"].([]any)[0].(map[string]any)["receipt_handle"] = strings.Repeat("f", 32)
		}},
		{"missing operation", func(r Report) { r["operation_results"] = r["operation_results"].([]any)[:2] }},
		{"wrong type", func(r Report) { r["operation_results"].([]any)[0].(map[string]any)["refs"] = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := Report(clone(map[string]any(baseline)).(map[string]any))
			tc.mutate(r)
			if p := partByID(t, CompareParts(v, r), "S14:0"); p.Pass {
				t.Fatal("plant escaped", p)
			}
		})
	}
	r := Report(clone(map[string]any(baseline)).(map[string]any))
	r["result"] = unsupported()
	if p := partByID(t, CompareParts(v, r), "S14:0"); !p.Pass {
		t.Fatal(p)
	}
	r["operation_results"].([]any)[2].(map[string]any)["retryable"] = true
	if p := partByID(t, CompareParts(v, r), "S14:2"); p.Pass {
		t.Fatal(p)
	}
	r = Report(clone(map[string]any(baseline)).(map[string]any))
	post := r["postconditions"].(map[string]any)
	post["record_refs"] = append(post["record_refs"].([]any), post["record_refs"].([]any)[0])
	if p := partByID(t, CompareParts(v, r), "S14:record_refs"); p.Pass {
		t.Fatal(p)
	}
}

// TestOperationRatchetControls proves unknown indexes/types, duplicate entries
// and a planted regression fail, with passing and newly passing controls.
func TestOperationRatchetControls(t *testing.T) {
	vs := []Verdict{{ID: "A", Parts: []PartVerdict{{ID: "A:0", Kind: "admit", Pass: true}, {ID: "A:1", Kind: "revise", Pass: false}, {ID: "A:2", Kind: "capture", Pass: true}}}}
	for _, text := range []string{"A:1", "A:2", "A:3", "A:0\nA:0"} {
		if _, err := CheckOperationRatchet(vs, text); err == nil {
			t.Fatal(text)
		}
	}
	if added, err := CheckOperationRatchet(vs, "A:0"); err != nil || len(added) != 0 {
		t.Fatal(added, err)
	}
	if added, err := CheckOperationRatchet(vs, ""); err != nil || len(added) != 1 || added[0] != "A:0" {
		t.Fatal(added, err)
	}
}

// TestExecutedSnapshotsReload proves every successful write in the public
// corpus produces a complete structurally/referentially valid snapshot; the
// constructor never sees expected results or comparison metadata.
func TestExecutedSnapshotsReload(t *testing.T) {
	schemas := schemasForTest(t)
	for _, v := range suite(t) {
		t.Run(v.ID(), func(t *testing.T) {
			input := v.Input()
			state, r := kernel.NewState(input.InitialState, schemas, freshHandle)
			if r != nil {
				t.Fatal(r)
			}
			for i, raw := range input.Operations {
				op := raw.(map[string]any)
				switch op["op"] {
				case "capture":
					_, r = state.Capture(int64(i), op["query"].(map[string]any))
				case "set_availability":
					_, r = state.SetAvailability(op)
				case "load":
					_, r = state.SeedLoad(op["actor"].(string), op["hidden_work"].(int64))
				default:
					_, r = state.Write(op)
				}
				if r == nil {
					if _, r = kernel.NewState(state.Snapshot(), schemas, freshHandle); r != nil {
						t.Fatal("post-write snapshot", r)
					}
				}
			}
		})
	}
}
