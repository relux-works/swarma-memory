package kernel

import (
	"fmt"
	"reflect"
	"testing"
)

// TestAdmissionForkIsolation proves a successful candidate write cannot alter its
// source, captured views remain private copies, and an issued handle cannot be
// reused by a fork even when it is absent from the persisted receipt registry.
func TestAdmissionForkIsolation(t *testing.T) {
	snapshot, q, ops := readFixture(t, "S14")
	source := stateForTest(t, snapshot)
	initial := copyJSON(q).(map[string]any)
	obj(initial["cut"])["memory"] = int64(100)
	view, f := source.Capture(7, initial)
	if f != nil {
		t.Fatal(f)
	}
	before := source.Snapshot()
	n := 100
	fork, f := source.Fork(func() (string, error) { n++; return fmt.Sprintf("%032x", n), nil })
	if f != nil {
		t.Fatal(f)
	}
	success(t, fork, obj(ops[0]))
	if !reflect.DeepEqual(before, source.Snapshot()) {
		t.Fatal("candidate altered source")
	}
	obj(fork.captures[7].view["changes"])["state"] = "tampered"
	if !reflect.DeepEqual(source.Captured(7), view) {
		t.Fatal("capture alias escaped")
	}
	reused, f := source.Fork(func() (string, error) { return view["authorized_snapshot_handle"].(string), nil })
	if f != nil {
		t.Fatal(f)
	}
	readRefused(t, reused, initial, Unavailable)
}

// TestOperationWireBoundary admits the nearby valid proposal shape and rejects
// unknown operation fields, unsupported operations and non-kernel numeric values.
// Shape acceptance alone never performs admission or changes a State.
func TestOperationWireBoundary(t *testing.T) {
	snapshot, ops := writeFixture(t, "S14")
	schemas := packageSchemas(t)
	source := stateForTest(t, snapshot)
	before := source.Snapshot()
	if r := schemas.ValidateWriteOperation(obj(ops[0])); r != nil {
		t.Fatal(r)
	}
	for _, change := range []func(map[string]any){func(op map[string]any) { op["extra"] = true }, func(op map[string]any) { op["op"] = "deliver" }, func(op map[string]any) { op["expected_generation"] = float64(0) }} {
		op := obj(copyJSON(ops[0]))
		change(op)
		if r := schemas.ValidateWriteOperation(op); r == nil {
			t.Fatal("invalid operation accepted")
		}
	}
	if !reflect.DeepEqual(before, source.Snapshot()) {
		t.Fatal("shape check admitted a write")
	}
}
