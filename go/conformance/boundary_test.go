package conformance

import (
	"fmt"
	"io/fs"
	"reflect"
	"strings"
	"testing"
)

// TestPointerPredicates proves RFC 6901 escaping, null presence, strict typed
// equality, array-only membership/size, and missing-path=false for all four tests.
func TestPointerPredicates(t *testing.T) {
	doc := map[string]any{"": nil, "a/b": map[string]any{"~key": []any{nil, int64(1), true, []any{"x"}}}, "text": "x", "object": map[string]any{}}
	for _, tc := range []struct {
		p     string
		want  any
		found bool
	}{{"", doc, true}, {"/", nil, true}, {"/a~1b/~0key/0", nil, true}, {"/a~1b/~0key/1", int64(1), true}, {"/a~1b/~0key/01", nil, false}, {"/a~1b/~0key/-", nil, false}, {"/a~1b/~0key/9", nil, false}, {"/text/x", nil, false}, {"/~2", nil, false}, {"no-slash", nil, false}} {
		t.Run("lookup"+tc.p, func(t *testing.T) {
			got, ok := lookup(doc, tc.p)
			if ok != tc.found || !reflect.DeepEqual(got, tc.want) {
				t.Fatal(got, ok)
			}
		})
	}
	for _, tc := range []struct {
		p, test string
		value   any
		want    bool
	}{
		{"/", "exists", nil, true}, {"/", "equals", nil, true}, {"/a~1b/~0key/1", "equals", true, false}, {"/a~1b/~0key/1", "equals", int64(1), true},
		{"/a~1b/~0key", "contains", []any{"x"}, true}, {"/a~1b/~0key", "contains", "x", false}, {"/a~1b/~0key", "contains", false, false},
		{"/a~1b/~0key", "size_equals", int64(4), true}, {"/a~1b/~0key", "size_equals", true, false}, {"/text", "contains", "x", false}, {"/object", "size_equals", int64(0), false},
	} {
		t.Run(tc.test+tc.p+fmt.Sprint(tc.value), func(t *testing.T) {
			if got := predicate(doc, map[string]any{"path": tc.p, "test": tc.test, "value": tc.value}); got != tc.want {
				t.Fatal(got)
			}
		})
	}
	for _, name := range []string{"exists", "equals", "contains", "size_equals"} {
		if predicate(doc, map[string]any{"path": "/missing", "test": name, "value": nil}) {
			t.Fatal(name, "matched absent path")
		}
	}
}

// TestNormalizationBoundary proves only declared handles are normalized, all
// fields survive equivalent-output comparisons, timestamps stay exact and
// extra/missing root fields and operation counts cannot pass.
func TestNormalizationBoundary(t *testing.T) {
	var v Vector
	for _, candidate := range suite(t) {
		if candidate.ID() == "S13" {
			v = candidate
			break
		}
	}
	base := oracle(v)
	for _, tc := range []struct {
		name          string
		mutate        func(Report)
		rule, pointer string
	}{
		{"extra root", func(r Report) { r["extra"] = true }, "equality", "/extra"},
		{"missing result", func(r Report) { delete(r, "result") }, "fresh_handles", "/result/authorized_snapshot_handle"},
		{"missing postconditions", func(r Report) { delete(r, "postconditions") }, "inventory", "/postconditions"},
		{"extra operation", func(r Report) { r["operation_results"] = append(r["operation_results"].([]any), unsupported()) }, "operation_results", "/operation_results"},
		{"missing operation", func(r Report) { r["operation_results"] = []any{} }, "operation_results", "/operation_results"},
		{"non JSON int", func(r Report) { r["extra"] = 1 }, "report", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := Report(clone(map[string]any(base)).(map[string]any))
			tc.mutate(r)
			wanted(t, v, r, tc.rule, tc.pointer)
		})
	}
	// Both pair endpoints are modified identically. Pair equality must not hide a
	// difference from the exact expected object, even for fresh-looking strings.
	for _, field := range []string{"status", "count", "budget", "quality", "availability", "timestamp", "undeclared_handle"} {
		t.Run(field, func(t *testing.T) {
			r := Report(clone(map[string]any(base)).(map[string]any))
			r["operation_results"].([]any)[0].(map[string]any)[field] = strings.Repeat("a", 32)
			r["result"].(map[string]any)[field] = strings.Repeat("a", 32)
			wanted(t, v, r, "equality", "/operation_results/0/"+field)
		})
	}
	// Each pair is checked even if expected is internally changed to accept the
	// altered right object: the equivalent-output obligation is independent.
	for _, candidate := range suite(t) {
		for _, raw := range candidate.document["normalization"].(map[string]any)["equivalent_outputs"].([]any) {
			pair := raw.(map[string]any)
			t.Run(candidate.ID()+"/pair", func(t *testing.T) {
				doc := clone(candidate.document).(map[string]any)
				r := oracle(candidate)
				right, _ := lookup(map[string]any(r), pair["right"].(string))
				right.(map[string]any)["budget"] = int64(99)
				e, _ := lookup(doc["expected"], pair["right"].(string))
				e.(map[string]any)["budget"] = int64(99)
				wanted(t, Vector{doc}, r, "equivalent_outputs", pair["right"].(string)+"/budget")
			})
		}
	}
	for _, bad := range []string{strings.Repeat("a", 31), strings.Repeat("a", 33), strings.Repeat("A", 32), strings.Repeat("g", 32), "@h1"} {
		t.Run("scheme/"+bad, func(t *testing.T) {
			r := Report(clone(map[string]any(base)).(map[string]any))
			replace(map[string]any(r), "/operation_results/0/authorized_snapshot_handle", bad)
			wanted(t, v, r, "fresh_handles", "/operation_results/0/authorized_snapshot_handle")
		})
	}
}

type deniedFS struct{}

func (deniedFS) Open(string) (fs.File, error) { return nil, fs.ErrPermission }

// TestUnavailableHarness proves missing dependencies and read failures are
// errors, never an empty passing suite. Duplicate results cannot weaken ratchets.
func TestUnavailableHarness(t *testing.T) {
	s := schemasForTest(t)
	for _, tc := range []struct {
		source         fs.FS
		missingSchemas bool
	}{{nil, false}, {deniedFS{}, false}, {deniedFS{}, true}} {
		schemas := s
		if tc.missingSchemas {
			schemas = nil
		}
		if vs, err := Load(tc.source, schemas); err == nil || vs != nil {
			t.Fatal(vs, err)
		}
	}
	if vs, err := Run(nil, KernelExecutor{}); err == nil || vs != nil {
		t.Fatal(vs, err)
	}
	if vs, err := Run(suite(t), nil); err == nil || vs != nil {
		t.Fatal(vs, err)
	}
	if _, err := CheckRatchet([]Verdict{{ID: "A", Pass: true}, {ID: "A", Pass: false}}, ""); err == nil || !strings.Contains(err.Error(), "duplicate result A") {
		t.Fatal(err)
	}
}

// TestRetainedFields proves existing quality, status, count, availability and
// timestamp values remain visible on both sides of an equivalent-output pair.
func TestRetainedFields(t *testing.T) {
	var v Vector
	for _, candidate := range suite(t) {
		if candidate.ID() == "S13" {
			v = candidate
		}
	}
	for _, p := range []string{"/items/0/support/evaluation", "/items/0/support/premise_quality", "/items/0/support/source_state", "/items/0/support/independent_root_count", "/items/0/confirmed_at"} {
		t.Run(p, func(t *testing.T) {
			r := oracle(v)
			for _, prefix := range []string{"/operation_results/0", "/result"} {
				if !replace(map[string]any(r), prefix+p, "control") {
					t.Fatal("missing control slot")
				}
			}
			wanted(t, v, r, "equality", "/operation_results/0"+p)
		})
	}
}

// TestRefusedInventories proves the baseline preserves every inventory across
// refusals, sorts the report copy and excludes absent custody without touching
// runtime state. Unknown harness operations publish no partial report.
func TestRefusedInventories(t *testing.T) {
	input := findVector(t, "S01").Input()
	input.Operations = nil
	input.Query["kind"] = "changes"
	input.Query["policy"].(map[string]any)["version"] = int64(999)
	input.InitialState["records"] = input.InitialState["records"].([]any)[:1]
	env := input.InitialState["records"].([]any)[0].(map[string]any)["envelope"].(map[string]any)
	ref := map[string]any{"id": "rec:gone", "version": int64(1)}
	runtime := input.InitialState["runtime"].(map[string]any)
	runtime["erased"] = []any{ref}
	runtime["dirty"] = []any{}
	item := func(id string, present bool) map[string]any {
		return map[string]any{"id": id, "present": present, "kind": "payload", "inputs": []any{}, "controlled": true, "reachable": true}
	}
	runtime["custody"] = []any{item("z", true), item("absent", false), item("a", true)}
	runtime["control_observations"] = []any{"stop_proceeded", "park_proceeded"}
	runtime["external_effects"] = []any{"effect"}
	before := clone(input.InitialState)
	r, err := (KernelExecutor{Schemas: schemasForTest(t)}).Execute(input)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"record_refs": []any{map[string]any{"id": env["id"], "version": env["version"]}}, "erased_refs": []any{ref}, "dirty": []any{}, "custody_present": []any{"a", "z"}, "control_observations": []any{"park_proceeded", "stop_proceeded"}, "external_effects": []any{"effect"}}
	if !reflect.DeepEqual(r["postconditions"], want) || !reflect.DeepEqual(input.InitialState, before) {
		t.Fatal(r["postconditions"])
	}
	if !reflect.DeepEqual(r["result"], map[string]any{"type": "refusal", "code": "policy_mismatch", "retryable": true}) {
		t.Fatal(r["result"])
	}
	input.Query["kind"] = "unknown"
	r, err = (KernelExecutor{Schemas: schemasForTest(t)}).Execute(input)
	if err != nil || !reflect.DeepEqual(r["result"], map[string]any{"type": "refusal", "code": "invalid_shape", "retryable": false}) {
		t.Fatal(r, err)
	}
	input.Operations = []any{map[string]any{"op": "unknown"}}
	if r, err = (KernelExecutor{Schemas: schemasForTest(t)}).Execute(input); err == nil || r != nil || !strings.Contains(err.Error(), "unsupported harness operation") {
		t.Fatal(r, err)
	}
}

// TestMarkerCollision proves a normalized handle cannot equal any undeclared
// JSON literal, even a string that resembles a normalization marker.
func TestMarkerCollision(t *testing.T) {
	if same(freshMarker{}, "@fresh") || same("@fresh", freshMarker{}) || !same(freshMarker{}, freshMarker{}) {
		t.Fatal("marker collides with JSON")
	}
}
