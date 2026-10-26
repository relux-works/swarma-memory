package conformance

import (
	"reflect"
	"testing"

	"github.com/relux-works/swarma-memory/go/kernel"
)

// The fixture-only raw stimulus executes real revisions, rejects malformed JSON
// and other operation kinds without changing observable state, and grants no
// additional public kernel operation.
func TestRawRevisionStimulus(t *testing.T) {
	schemas := schemasForTest(t)
	executor := KernelExecutor{Schemas: schemas}
	var vector Vector
	for _, v := range suite(t) {
		if v.ID() == "S17" {
			vector = v
		}
	}
	input := vector.Input()
	wire, r := kernel.CanonicalJSON(input.Operations[0])
	if r != nil {
		t.Fatal(r)
	}
	input.Operations = input.Operations[:1]
	positive, e := executor.Execute(input)
	if e != nil {
		t.Fatal(e)
	}
	raw := map[string]any{"op": "revise_raw", "raw_json": string(wire)}
	input.Operations = []any{raw}
	got, e := executor.Execute(input)
	if e != nil || got["operation_results"].([]any)[0].(map[string]any)["type"] != "receipt" || !reflect.DeepEqual(got["postconditions"], positive["postconditions"]) {
		t.Fatal(got, e)
	}
	input.Operations = nil
	baseline, e := executor.Execute(input)
	if e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct{ wire, code string }{
		{`{`, "invalid_json"},
		{`{"op":"revise","op":"revise"}`, "invalid_json"},
		{`[]`, "invalid_shape"},
		{`{"op":"admit"}`, "invalid_shape"},
		{`{"op":"revise"}`, "invalid_shape"},
	} {
		raw["raw_json"] = tc.wire
		input.Operations = []any{raw}
		got, e = executor.Execute(input)
		want := map[string]any{"type": "refusal", "code": tc.code, "retryable": false}
		if e != nil || !reflect.DeepEqual(got["operation_results"], []any{want}) || !reflect.DeepEqual(got["postconditions"], baseline["postconditions"]) || !reflect.DeepEqual(got["result"], baseline["result"]) {
			t.Fatal(tc, got, e)
		}
	}
	state, refusal := kernel.NewState(input.InitialState, schemas, freshHandle)
	if refusal != nil {
		t.Fatal(refusal)
	}
	before := state.Snapshot()
	if result, refusal := state.Write(raw); result != nil || refusal == nil || refusal.Code != kernel.UnsupportedOperation || !reflect.DeepEqual(before, state.Snapshot()) {
		t.Fatal(result, refusal)
	}
}
