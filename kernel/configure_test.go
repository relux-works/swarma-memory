package kernel

import (
	"fmt"
	"reflect"
	"testing"
)

// TestConfigureAuthorityTransition proves a trusted reader/writer revocation
// hides existing data and refuses new admission, without deleting history or
// reinstalling historical grants on a fork. Malformed changes are atomic.
func TestConfigureAuthorityTransition(t *testing.T) {
	snapshot, q, ops := readFixture(t, "S14")
	state := stateForTest(t, snapshot)
	success(t, state, obj(ops[0]))
	obj(q["cut"])["memory"] = int64(101)
	view, f := state.Read(q)
	if f != nil || len(arr(view["items"])) != 1 {
		t.Fatal(view, f)
	}
	saved := state.Snapshot()
	p := obj(copyJSON(saved["policy"]))
	p["grants"] = []any{}
	if f := state.Configure(p, arr(saved["projection_rules"])); f != nil {
		t.Fatal(f)
	}
	obj(p["limits"])["max_records"] = int64(0)
	n := 100
	fork, f := state.Fork(func() (string, error) { n++; return fmt.Sprintf("%032x", n), nil })
	if f != nil {
		t.Fatal(f)
	}
	view, f = fork.Read(q)
	if f != nil || len(arr(view["items"])) != 0 {
		t.Fatal(view, f)
	}
	if len(arr(fork.Snapshot()["records"])) != 1 || obj(obj(fork.Snapshot()["policy"])["limits"])["max_records"] == int64(0) {
		t.Fatal("history lost or alias retained")
	}
	if _, f := fork.Write(obj(ops[0])); f == nil || f.Code != NotAuthorized {
		t.Fatal(f)
	}
	before := state.Snapshot()
	bad := obj(copyJSON(before["policy"]))
	bad["extra"] = true
	if f := state.Configure(bad, arr(saved["projection_rules"])); f == nil || f.Code != InvalidShape {
		t.Fatal(f)
	}
	bad = obj(copyJSON(before["policy"]))
	bad["lineage_facts"] = []any{}
	if f := state.Configure(bad, arr(saved["projection_rules"])); f == nil || f.Code != InvalidReference {
		t.Fatal(f)
	}
	if !reflect.DeepEqual(before, state.Snapshot()) {
		t.Fatal("rejected configuration changed state")
	}
	if f := state.Configure(obj(saved["policy"]), arr(saved["projection_rules"])); f != nil {
		t.Fatal(f)
	}
	view, f = state.Read(q)
	if f != nil || len(arr(view["items"])) != 1 {
		t.Fatal(view, f)
	}
}

// TestConfigureTeamHistory proves repeated current-policy changes preserve a
// previously admitted team declaration while never resurrecting its admit right.
func TestConfigureTeamHistory(t *testing.T) {
	snapshot, ops := writeFixture(t, "S14")
	op := obj(ops[0])
	env(arr(op["proposals"])[0])["perspective"] = map[string]any{"kind": "team", "principal": "subj:h1"}
	state := stateForTest(t, snapshot)
	success(t, state, op)
	for i := 0; i < 2; i++ {
		saved := state.Snapshot()
		p := obj(saved["policy"])
		p["grants"] = []any{}
		if f := state.Configure(p, arr(saved["projection_rules"])); f != nil {
			t.Fatal(i, f)
		}
	}
	fork, f := state.Fork(mintForTest())
	if f != nil {
		t.Fatal(f)
	}
	if len(arr(obj(fork.Snapshot()["policy"])["grants"])) != 0 || len(arr(fork.Snapshot()["records"])) != 1 {
		t.Fatal("historical grant reinstalled or history lost")
	}
	if _, f := fork.Write(op); f == nil || f.Code != NotAuthorized {
		t.Fatal(f)
	}
}
