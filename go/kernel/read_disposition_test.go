package kernel

import "testing"

// TestReadDispositionAssertions retains the S02 review witness: a current fence
// or erasure omits payloads before selection, proof work and metadata, including
// historical cuts. Unfenced controls retain alpha and both polarity witnesses.
func TestReadDispositionAssertions(t *testing.T) {
	for _, cut := range []int64{3, 100} {
		snapshot, q, _ := readFixture(t, "S02")
		obj(snapshot["runtime"])["committed_cuts"] = set([]any{int64(3), int64(100)})
		obj(q["cut"])["memory"] = cut
		live := readSuccess(t, stateForTest(t, snapshot), q)
		if contentField(map[string]any{"body": firstItem(t, live)}, "value") != "alpha" {
			t.Fatal("missing payload positive control", live)
		}
		for _, polarity := range []string{"support", "oppose"} {
			ch := channelOf(t, live, polarity)
			if ch["witness"] != "present" || ch["evaluation"] != "complete" {
				t.Fatal("missing witness positive control", live)
			}
		}
		for _, disposition := range []string{"fences", "erased", "both"} {
			for _, kind := range []string{"recall", "explain", "changes"} {
				for _, explicit := range []bool{false, true} {
					candidate := copyJSON(snapshot).(map[string]any)
					for _, field := range []string{"fences", "erased"} {
						if disposition == field || disposition == "both" {
							obj(candidate["runtime"])[field] = copyJSON(obj(q["scope"])["targets"])
						}
					}
					obj(candidate["runtime"])["erasure_generation"] = int64(1)
					query := copyJSON(q).(map[string]any)
					query["kind"] = kind
					if !explicit {
						obj(query["scope"])["targets"] = []any{}
					}
					// Compare every observable field with an authorized empty projection.
					empty := copyJSON(snapshot).(map[string]any)
					for _, grant := range arr(obj(empty["policy"])["grants"]) {
						obj(grant)["records"] = []any{}
					}
					for _, zero := range []bool{false, true} {
						if zero {
							for field := range obj(query["bounds"]) {
								obj(query["bounds"])[field] = int64(0)
							}
						}
						want := readSuccess(t, stateForTest(t, empty), query)
						got := readSuccess(t, stateForTest(t, candidate), query)
						if len(arr(got["items"])) != 0 || !equalJSON(comparableView(got), comparableView(want)) {
							t.Fatalf("cut=%d %s %s explicit=%v zero=%v disclosed fenced data: %v", cut, disposition, kind, explicit, zero, got)
						}
					}
				}
			}
		}
	}
}

// TestReadDispositionSources retains the B13 review witness: a fence disables
// current-required resolution even at an old cut, without revoking authorized
// headers or separately retained/independent checks. Hidden headers remain a
// permission filter with no availability gap. These reads mutate no snapshot.
func TestReadDispositionSources(t *testing.T) {
	for _, requirement := range []string{"current", "retained", "independent"} {
		for _, cut := range []int64{3, 100} {
			snapshot, q, _ := readFixture(t, "B13")
			obj(snapshot["runtime"])["committed_cuts"] = set([]any{int64(3), int64(100)})
			obj(q["cut"])["memory"] = cut
			var source any
			for _, r := range arr(snapshot["records"]) {
				if env(r)["kind"] == "source" {
					source = r
					body(r)["availability"] = "resolvable"
				}
				if env(r)["kind"] == "assessment" {
					body(r)["source_requirement"] = requirement
				}
			}
			for _, access := range arr(obj(snapshot["policy"])["source_access"]) {
				obj(access)["resolvable"] = true
			}
			live := readSuccess(t, stateForTest(t, snapshot), q)
			ch := channelOf(t, live, "support")
			if ch["witness"] != "present" || ch["evaluation"] != "complete" || ch["source_state"] != "resolvable_now" || len(arr(live["cutoffs"])) != 0 {
				t.Fatal("missing live source control", live)
			}
			for _, disposition := range []string{"fences", "erased", "both"} {
				candidate := copyJSON(snapshot).(map[string]any)
				for _, field := range []string{"fences", "erased"} {
					if disposition == field || disposition == "both" {
						obj(candidate["runtime"])[field] = []any{ref(source)}
					}
				}
				obj(candidate["runtime"])["erasure_generation"] = int64(1)
				v := readSuccess(t, stateForTest(t, candidate), q)
				ch = channelOf(t, v, "support")
				witness, evaluation, state := "present", "complete", "prior_assessment_only"
				cutoffs := []any{}
				if requirement == "current" {
					witness, evaluation = "not_found", "incomplete"
					cutoffs = []any{"source_unavailable"}
				} else if requirement == "independent" {
					state = "independent_attestation"
				}
				if ch["witness"] != witness || ch["evaluation"] != evaluation || ch["source_state"] != state || !equalJSON(v["cutoffs"], cutoffs) || !equalJSON(firstItem(t, v)["source_refs"], []any{ref(source)}) {
					t.Fatalf("%s cut=%d %s: %v", requirement, cut, disposition, v)
				}
				oppose := channelOf(t, v, "oppose")
				if oppose["witness"] != "not_found" || oppose["evaluation"] != "complete" || oppose["source_state"] != "prior_assessment_only" {
					t.Fatal("disposition fabricated opposition", oppose)
				}
				// Current read/use/metadata still govern the surviving source header.
				for _, grant := range arr(obj(candidate["policy"])["grants"]) {
					obj(grant)["records"] = []any{"rec:a", "rec:ep"}
				}
				hidden := readSuccess(t, stateForTest(t, candidate), q)
				ch = channelOf(t, hidden, "support")
				if ch["witness"] != "not_found" || ch["evaluation"] != "complete" || len(arr(hidden["cutoffs"])) != 0 || len(arr(firstItem(t, hidden)["source_refs"])) != 0 {
					t.Fatal("hidden header leaked availability", hidden)
				}
			}
		}
	}
}

// TestReadDispositionLineage proves known transitive content inputs close
// assertion/assessment payloads and source bytes, including incomplete lower
// bounds and intermediates beyond an old knowledge cut. Mere source association
// remains distinct, as exercised by TestReadDispositionSources.
func TestReadDispositionLineage(t *testing.T) {
	for _, kind := range []string{"assertion", "assessment", "source"} {
		for _, complete := range []bool{true, false} {
			snapshot, q, _ := readFixture(t, "B13")
			q["kind"] = "explain"
			obj(q["cut"])["memory"] = int64(3)
			obj(snapshot["runtime"])["committed_cuts"] = set([]any{int64(3), int64(100)})
			var source, affected any
			for _, r := range arr(snapshot["records"]) {
				if env(r)["kind"] == kind {
					affected = r
				}
				if env(r)["kind"] == "source" {
					source = r
					body(r)["availability"] = "resolvable"
				}
			}
			for _, access := range arr(obj(snapshot["policy"])["source_access"]) {
				obj(access)["resolvable"] = true
			}
			bridge := copyJSON(source)
			env(bridge)["id"] = "rec:bridge"
			obj(env(bridge)["recorded"])["sequence"] = int64(4)
			ancestor := copyJSON(source)
			env(ancestor)["id"] = "rec:ancestor"
			obj(env(ancestor)["recorded"])["sequence"] = int64(5)
			snapshot["records"] = append(arr(snapshot["records"]), bridge, ancestor)
			facts := arr(obj(snapshot["policy"])["lineage_facts"])
			direct := copyJSON(facts[0]).(map[string]any)
			direct["output"] = ref(ancestor)
			middle := copyJSON(direct).(map[string]any)
			middle["output"], middle["kind"], middle["inputs"] = ref(bridge), "deterministic", []any{ref(ancestor)}
			env(bridge)["lineage"] = copyJSON(middle["inputs"])
			for _, raw := range facts {
				f := obj(raw)
				if equalJSON(f["output"], ref(affected)) {
					f["kind"], f["inputs"], f["complete"] = "deterministic", []any{ref(bridge)}, complete
					env(affected)["lineage"] = copyJSON(f["inputs"])
					if !complete {
						env(affected)["lineage"] = "unknown"
					}
				}
			}
			obj(snapshot["policy"])["lineage_facts"] = append(facts, direct, middle)
			live := readSuccess(t, stateForTest(t, snapshot), q)
			if channelOf(t, live, "support")["witness"] != "present" || len(arr(live["cutoffs"])) != 0 {
				t.Fatal("missing unfenced transitive control", live)
			}
			for _, field := range []string{"fences", "erased"} {
				candidate := copyJSON(snapshot).(map[string]any)
				obj(candidate["runtime"])[field] = []any{ref(ancestor)}
				v := readSuccess(t, stateForTest(t, candidate), q)
				if kind == "assertion" {
					if len(arr(v["items"])) != 0 || v["currentness"] != "none" || len(arr(v["cutoffs"])) != 0 {
						t.Fatal("derived assertion survived disposition", v)
					}
				} else {
					ch := channelOf(t, v, "support")
					evaluation, cutoffs := "complete", []any{}
					if kind == "source" {
						evaluation, cutoffs = "incomplete", []any{"source_unavailable"}
					}
					if ch["witness"] != "not_found" || ch["evaluation"] != evaluation || !equalJSON(v["cutoffs"], cutoffs) {
						t.Fatalf("kind=%s complete=%v %s: %v", kind, complete, field, v)
					}
				}
				if len(arr(obj(v["explanation"])["paths"])) != 0 {
					t.Fatal("affected evidence survived in explanation", v)
				}
			}
		}
	}
}
