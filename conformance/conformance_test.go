package conformance

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/relux-works/swarma-memory/kernel"
)

func schemasForTest(t *testing.T) *kernel.Schemas {
	t.Helper()
	s, r := kernel.LoadSchemas(os.DirFS("../spec/kernel/schemas"))
	if r != nil {
		t.Fatal(r)
	}
	return s
}
func suite(t *testing.T) []Vector {
	t.Helper()
	vs, err := Load(os.DirFS("../spec/kernel/vectors/semantic"), schemasForTest(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(vs) != 66 {
		t.Fatalf("got %d vectors; want 66", len(vs))
	}
	return vs
}

type executeFunc func(Input) (Report, error)

func (f executeFunc) Execute(i Input) (Report, error) { return f(i) }

// The oracle belongs only to tests. Distinct fixture placeholder labels get
// distinct deterministic 128-bit encodings; equal labels share one encoding.
// This is a comparator control, not a statistical randomness certification.
func oracle(v Vector) Report {
	r := clone(v.document["expected"]).(map[string]any)
	labels := map[string]string{}
	for _, raw := range v.document["normalization"].(map[string]any)["fresh_handles"].([]any) {
		p := raw.(string)
		label, _ := lookup(r, p)
		key := label.(string)
		h, ok := labels[key]
		if !ok {
			h = fmt.Sprintf("%032x", len(labels)+1)
			labels[key] = h
		}
		replace(r, p, h)
	}
	return Report(r)
}
func wanted(t *testing.T, v Vector, r Report, rule, pointer string) {
	t.Helper()
	got := Compare(v, r)
	if got.Pass || got.Rule != rule || got.Pointer != pointer || !strings.Contains(got.Reason, rule+" at ") {
		t.Fatalf("got %+v; want %s at %q", got, rule, pointer)
	}
}

// TestOracle proves all 66 expected reports with valid generated handles pass
// through the runner, and execution-only inputs cannot mutate fixture data.
func TestOracle(t *testing.T) {
	vs := suite(t)
	byID := map[string]Vector{}
	for _, v := range vs {
		byID[v.ID()] = v
	}
	verdicts, err := Run(vs, executeFunc(func(i Input) (Report, error) {
		v := byID[i.ID]
		i.Query["kind"] = "mutated"
		i.InitialState["records"] = nil
		i.Operations = nil
		return oracle(v), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range verdicts {
		t.Run(v.ID, func(t *testing.T) {
			if !v.Pass {
				t.Fatal(v.Reason)
			}
		})
	}
	t.Logf("oracle: %d/66 pass", len(verdicts))
}

// TestMutationControls plants each applicable failure in every vector. Exact
// rule and pointer assertions distinguish intended detection from setup errors.
// Reorders of equal reports are unobservable and are not applicable.
func TestMutationControls(t *testing.T) {
	counts := map[string]int{}
	for _, v := range suite(t) {
		t.Run(v.ID(), func(t *testing.T) {
			base := oracle(v)
			before := clone(map[string]any(base))
			for _, kind := range []string{"leaf", "removed", "added"} {
				t.Run(kind, func(t *testing.T) {
					r := Report(clone(map[string]any(base)).(map[string]any))
					result := r["result"].(map[string]any)
					p := "/type"
					switch kind {
					case "leaf":
						result["type"] = "control"
					case "removed":
						delete(result, "type")
					case "added":
						result["__control"] = true
						p = "/__control"
					}
					rule, pointer := "equality", "/result"+p
					for _, raw := range v.document["normalization"].(map[string]any)["equivalent_outputs"].([]any) {
						pair := raw.(map[string]any)
						if pair["right"] == "/result" {
							rule, pointer = "equivalent_outputs", "/result"+p
							break
						}
					}
					wanted(t, v, r, rule, pointer)
					counts[kind]++
				})
			}
			norm := v.document["normalization"].(map[string]any)
			for _, kind := range []string{"equal_handles", "distinct_handles", "fresh_handles"} {
				list := norm[kind].([]any)
				if len(list) == 0 {
					continue
				}
				t.Run(kind, func(t *testing.T) {
					r := Report(clone(map[string]any(base)).(map[string]any))
					p := ""
					value := any("invalid-handle")
					if kind == "fresh_handles" {
						p = list[0].(string)
					} else {
						group := list[0].([]any)
						p = group[1].(string)
						if kind == "equal_handles" {
							value = strings.Repeat("f", 32)
						} else {
							value, _ = lookup(map[string]any(r), group[0].(string)) // Collapse the entire equal class to preserve equality constraints.
							old, _ := lookup(map[string]any(r), p)
							for _, slot := range norm["fresh_handles"].([]any) {
								x, _ := lookup(map[string]any(r), slot.(string))
								if same(x, old) {
									replace(map[string]any(r), slot.(string), value)
								}
							}
						}
					}
					replace(map[string]any(r), p, value)
					wanted(t, v, r, kind, p)
					counts[kind]++
				})
			}
			// Every forbidden predicate gets its own independent plant, not just one per vector.
			for n, raw := range v.document["forbidden"].([]any) {
				f := raw.(map[string]any)
				t.Run(fmt.Sprintf("forbidden/%d", n), func(t *testing.T) {
					r := Report(clone(map[string]any(base)).(map[string]any))
					value := clone(f["value"])
					switch f["test"] {
					case "contains":
						value = []any{value}
					case "size_equals":
						value = make([]any, int(value.(int64)))
					case "exists":
						value = nil
					}
					plant(t, map[string]any(r), f["path"].(string), value)
					// Earlier predicates may also become true when an array inventory is replaced.
					first := ""
					for _, earlier := range v.document["forbidden"].([]any) {
						e := earlier.(map[string]any)
						if predicate(map[string]any(r), e) {
							first = e["path"].(string)
							break
						}
					}
					if first == "" {
						t.Fatal("plant did not trigger predicate")
					}
					wanted(t, v, r, "forbidden", first)
					counts["forbidden"]++
				})
			}
			post := base["postconditions"].(map[string]any)
			// Exercise each applicable inventory, including singleton removal.
			for _, key := range inventories {
				list := post[key].([]any)
				for _, kind := range []string{"inventory_missing", "inventory_unsorted"} {
					if len(list) == 0 || kind == "inventory_unsorted" && len(list) < 2 {
						continue
					}
					t.Run(kind+"/"+key, func(t *testing.T) {
						r := Report(clone(map[string]any(base)).(map[string]any))
						copy := r["postconditions"].(map[string]any)[key].([]any)
						p := "/postconditions/" + key
						rule := "equality"
						pointer := p + fmt.Sprintf("/%d", len(copy)-1)
						if kind == "inventory_unsorted" {
							copy[0], copy[1] = copy[1], copy[0]
							rule = "inventory"
							pointer = p + "/1"
						} else {
							r["postconditions"].(map[string]any)[key] = copy[:len(copy)-1]
						}
						// A missing element may deliberately trigger a forbidden size constraint first.
						for _, raw := range v.document["forbidden"].([]any) {
							f := raw.(map[string]any)
							if predicate(map[string]any(r), f) {
								rule, pointer = "forbidden", f["path"].(string)
								break
							}
						}
						wanted(t, v, r, rule, pointer)
						counts[kind]++
					})
				}
			}
			// Use the first observable pair. Pointer/rule witnesses for the corpus are
			// asserted below, including handle and forbidden constraints retained on reorder.
			ops := base["operation_results"].([]any)
		outer:
			for i := 0; i < len(ops); i++ {
				for j := i + 1; j < len(ops); j++ {
					if reflect.DeepEqual(ops[i], ops[j]) {
						continue
					}
					t.Run("reorder", func(t *testing.T) {
						r := Report(clone(map[string]any(base)).(map[string]any))
						list := r["operation_results"].([]any)
						list[i], list[j] = list[j], list[i]
						witness, ok := reorderWitnesses[v.ID()]
						if !ok {
							t.Fatal("missing independent reorder diagnostic")
						}
						wanted(t, v, r, witness[0], witness[1])
						counts["reorder"]++
					})
					break outer
				}
			}
			if !reflect.DeepEqual(before, map[string]any(base)) {
				t.Fatal("comparator mutated report")
			}
		})
	}
	expectedCounts := map[string]int{"leaf": 66, "removed": 66, "added": 66, "reorder": 28, "equal_handles": 61, "distinct_handles": 35, "fresh_handles": 66, "forbidden": 160, "inventory_missing": 77, "inventory_unsorted": 59}
	if !reflect.DeepEqual(counts, expectedCounts) {
		t.Fatalf("mutation applicability changed: %v; want %v", counts, expectedCounts)
	}
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		t.Logf("mutation %s: %d intended rejections", k, counts[k])
	}
}

// plant creates absent object/array paths for forbidden-predicate controls.
func plant(t *testing.T, root any, p string, value any) {
	t.Helper()
	parts, err := tokens(p)
	if err != nil || len(parts) == 0 {
		t.Fatalf("bad plant pointer %q", p)
	}
	var set func(any, []string) any
	set = func(node any, parts []string) any {
		if len(parts) == 0 {
			return value
		}
		key := parts[0]
		switch x := node.(type) {
		case map[string]any:
			x[key] = set(x[key], parts[1:])
			return x
		case []any:
			n := 0
			if _, err := fmt.Sscanf(key, "%d", &n); err != nil {
				t.Fatal(err)
			}
			for len(x) <= n {
				x = append(x, nil)
			}
			x[n] = set(x[n], parts[1:])
			return x
		default:
			return set(map[string]any{}, parts)
		}
	}
	set(root, parts)
}

// TestKernelWrites proves every in-scope admission result matches, all matched
// operations are persisted in the ratchet, and queries remain honest refusals.
func TestKernelWrites(t *testing.T) {
	vs := suite(t)
	executor := KernelExecutor{Schemas: schemasForTest(t)}
	verdicts, err := Run(vs, executor)
	if err != nil {
		t.Fatal(err)
	}
	text, err := os.ReadFile("passing.txt")
	if err != nil {
		t.Fatal(err)
	}
	added, err := CheckRatchet(verdicts, string(text))
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range added {
		t.Log("newly passing vector:", id)
	}
	text, err = os.ReadFile("passing-ops.txt")
	if err != nil {
		t.Fatal(err)
	}
	added, err = CheckOperationRatchet(verdicts, string(text))
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range added {
		t.Log("newly matching operation:", id)
	}
	if len(added) != 0 {
		t.Fatal("persist newly matching admission operations in passing-ops.txt")
	}
	excluded := map[string]string{"P11:13": "prior unsupported revoke", "P11:14": "prior unsupported revoke", "S26:1": "prior unsupported erase"}
	for i, v := range vs {
		input := v.Input()
		before := clone(input.InitialState)
		report, err := executor.Execute(input)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(report["result"], unsupported()) || !reflect.DeepEqual(before, input.InitialState) {
			t.Fatal(v.ID(), "query refusal or input isolation")
		}
		if p, detail := inventoryError(map[string]any(report)); detail != "" {
			t.Fatal(p, detail)
		}
		for _, p := range verdicts[i].Parts {
			if admission(p.Kind) && !p.Pass {
				if excluded[p.ID] == "" {
					t.Errorf("%s: %s at %s", p.ID, p.Reason, p.Pointer)
				} else {
					t.Log(p.ID, excluded[p.ID])
					delete(excluded, p.ID)
				}
			}
		}
	}
	if len(excluded) != 0 {
		t.Fatal("exclusions must be revisited when behavior changes", excluded)
	}
	counts := CountParts(verdicts)
	for kind, want := range map[string]Agreement{"admit": {42, 45}, "admit_raw": {2, 2}, "revise": {26, 26}, "load": {1, 1}} {
		if counts[kind] != want {
			t.Errorf("%s: %+v", kind, counts[kind])
		}
	}
}

// TestRatchetControls proves regressions, typos and duplicates fail; passing
// requirements and newly passing IDs have separate positive controls.
func TestRatchetControls(t *testing.T) {
	verdicts := []Verdict{{ID: "A", Pass: true}, {ID: "B", Pass: false}}
	for _, tc := range []struct{ text, want string }{{"B", "required vector B failed"}, {"C", "unknown id C"}, {"A\nA", "duplicate id A"}} {
		t.Run(tc.want, func(t *testing.T) {
			_, err := CheckRatchet(verdicts, tc.text)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatal(err)
			}
		})
	}
	added, err := CheckRatchet(verdicts, "# comment\nA\n")
	if err != nil || len(added) != 0 {
		t.Fatal(added, err)
	}
	added, err = CheckRatchet(verdicts, "")
	if err != nil || !reflect.DeepEqual(added, []string{"A"}) {
		t.Fatal(added, err)
	}
}

// TestHarnessErrors proves malformed/empty/mixed suites and executor failures
// cannot publish a partial successful result; a valid vector is the control.
func TestHarnessErrors(t *testing.T) {
	schemas := schemasForTest(t)
	v := suite(t)[0]
	data, _ := kernel.CanonicalJSON(v.document)
	for _, tc := range []struct {
		name  string
		files fstest.MapFS
		want  string
	}{
		{"valid", fstest.MapFS{"v.json": {Data: data}}, ""},
		{"empty", fstest.MapFS{}, "no semantic vectors"},
		{"bad JSON", fstest.MapFS{"v.json": {Data: []byte(`{"id":"a","id":"b"}`)}}, "invalid_json"},
		{"bad shape", fstest.MapFS{"v.json": {Data: []byte(`{}`)}}, "invalid_shape"},
		{"partial", fstest.MapFS{"a.json": {Data: data}, "z.json": {Data: []byte(`{}`)}}, "invalid_shape"},
		{"duplicate", fstest.MapFS{"a.json": {Data: data}, "b.json": {Data: data}}, "duplicate vector id"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			vs, err := Load(tc.files, schemas)
			if tc.want == "" {
				if err != nil || len(vs) != 1 {
					t.Fatal(vs, err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.want) || vs != nil {
				t.Fatal(vs, err)
			}
		})
	}
	for _, kind := range []string{"profile", "operation_results", "fresh_handles", "equal_handles", "pointer", "inventory", "forbidden", "equivalent_outputs"} {
		t.Run(kind, func(t *testing.T) {
			doc := clone(v.document).(map[string]any)
			n := doc["normalization"].(map[string]any)
			switch kind {
			case "profile":
				doc["profile"] = "deployment"
			case "operation_results":
				doc["expected"].(map[string]any)["operation_results"] = []any{}
			case "fresh_handles":
				n["fresh_handles"] = []any{"/result/missing"}
			case "equal_handles":
				n["equal_handles"] = []any{[]any{"/missing", "/result"}}
			case "equivalent_outputs":
				n["equivalent_outputs"] = []any{map[string]any{"left": "/operation_results/0", "right": "/result"}}
			case "pointer":
				doc["forbidden"].([]any)[0].(map[string]any)["path"] = "/~2"
			case "inventory":
				post := doc["expected"].(map[string]any)["postconditions"].(map[string]any)
				list := post["record_refs"].([]any)
				list[0], list[1] = list[1], list[0]
			case "forbidden":
				doc["forbidden"].([]any)[0].(map[string]any)["test"] = "size_equals"
				doc["forbidden"].([]any)[0].(map[string]any)["value"] = true
			}
			b, _ := kernel.CanonicalJSON(doc)
			got, err := Load(fstest.MapFS{"v.json": {Data: b}}, schemas)
			if err == nil || got != nil {
				t.Fatal("malformed metadata accepted", kind)
			}
		})
	}
	if got, err := Run([]Vector{v}, executeFunc(func(Input) (Report, error) { return nil, errors.New("control failure") })); err == nil || !strings.Contains(err.Error(), "control failure") || got != nil {
		t.Fatal(got, err)
	}
}

// These corpus witnesses name the first normative violation of the selected
// swap: a forbidden value, missing declared handle, or typed field difference.
var reorderWitnesses = map[string][2]string{
	"B01": {"fresh_handles", "/operation_results/4/authorized_snapshot_handle"},
	"B02": {"fresh_handles", "/operation_results/1/receipt_handle"},
	"B07": {"fresh_handles", "/operation_results/0/authorized_snapshot_handle"},
	"B12": {"fresh_handles", "/operation_results/0/receipt_handle"},
	"P02": {"equality", "/operation_results/0/code"},
	"P03": {"fresh_handles", "/operation_results/0/receipt_handle"},
	"P04": {"equality", "/operation_results/0/items/0/oppose/freshness"},
	"P05": {"forbidden", "/operation_results/0/type"},
	"P06": {"fresh_handles", "/operation_results/0/authorized_snapshot_handle"},
	"P08": {"forbidden", "/operation_results/2/type"},
	"P10": {"fresh_handles", "/operation_results/0/receipt_handle"},
	"P11": {"equality", "/operation_results/0/code"},
	"P12": {"fresh_handles", "/operation_results/0/authorized_snapshot_handle"},
	"P13": {"equality", "/operation_results/0/code"},
	"P14": {"fresh_handles", "/operation_results/0/receipt_handle"},
	"P15": {"equality", "/operation_results/0/items/0/issuer"},
	"S01": {"fresh_handles", "/operation_results/1/items/0/support/authorized_snapshot_handle"},
	"S13": {"fresh_handles", "/operation_results/0/authorized_snapshot_handle"},
	"S14": {"fresh_handles", "/operation_results/0/receipt_handle"},
	"S20": {"equality", "/operation_results/0/custody/0"},
	"S24": {"fresh_handles", "/operation_results/0/authorized_snapshot_handle"},
	"S25": {"equality", "/operation_results/0/custody/0"},
	"S26": {"fresh_handles", "/operation_results/0/receipt_handle"},
	"S27": {"fresh_handles", "/operation_results/0/authorized_snapshot_handle"},
	"S32": {"forbidden", "/operation_results/1/items/0/support/source_state"},
	"S39": {"fresh_handles", "/operation_results/2/authorized_snapshot_handle"},
	"S40": {"fresh_handles", "/operation_results/0/receipt_handle"},
	"S41": {"fresh_handles", "/operation_results/0/receipt_handle"},
}
