package kernel

import (
	"fmt"
	"math/rand"
	"os"
	"reflect"
	"sync"
	"testing"
)

func readFixture(t *testing.T, id string) (map[string]any, map[string]any, []any) {
	t.Helper()
	b, e := os.ReadFile("../spec/kernel/vectors/semantic/" + id + ".json")
	if e != nil {
		t.Fatal(e)
	}
	v, r := DecodeJSON(b)
	if r != nil {
		t.Fatal(r)
	}
	m := obj(v)
	return obj(m["initial_state"]), obj(m["query"]), arr(m["operations"])
}
func readSuccess(t *testing.T, s *State, q map[string]any) map[string]any {
	t.Helper()
	before := s.Snapshot()
	v, r := s.Read(q)
	if r != nil || v["type"] != "view" {
		t.Fatal(v, r)
	}
	if !reflect.DeepEqual(before, s.Snapshot()) {
		t.Fatal("read changed admitted snapshot")
	}
	if !s.schemas.roots[packageSchema+"view"].matches(v, nil) {
		t.Fatal("invalid view shape", v)
	}
	return v
}
func firstItem(t *testing.T, v map[string]any) map[string]any {
	t.Helper()
	if len(arr(v["items"])) != 1 {
		t.Fatal("expected exactly one selected item", v)
	}
	return obj(arr(v["items"])[0])
}
func channelOf(t *testing.T, v map[string]any, p string) map[string]any {
	return obj(firstItem(t, v)[p])
}
func readRefused(t *testing.T, s *State, q map[string]any, code RefusalCode) {
	t.Helper()
	before := s.Snapshot()
	v, r := s.Read(q)
	want, _ := NewRefusal(code)
	if v != nil || !reflect.DeepEqual(r, want) || !reflect.DeepEqual(before, s.Snapshot()) {
		t.Fatalf("got %v %v; want atomic refusal %v", v, r, want)
	}
}

// TestReadPermutationDeterminism proves canonical outputs (except independently
// minted handles) are invariant under these input/configuration permutations.
func TestReadPermutationDeterminism(t *testing.T) {
	for _, id := range []string{"S03", "S07", "S28", "S32", "P15"} {
		t.Run(id, func(t *testing.T) {
			snapshot, q, _ := readFixture(t, id)
			baseline := key(comparableView(readSuccess(t, stateForTest(t, snapshot), q)))
			rng := rand.New(rand.NewSource(731))
			for i := 0; i < 12; i++ {
				candidate := copyJSON(snapshot).(map[string]any)
				lists := []any{candidate["records"], candidate["domain_schemas"], candidate["projection_rules"]}
				for _, name := range []string{"grants", "reviews", "lineage_facts", "authority_events", "source_access", "handles"} {
					lists = append(lists, obj(candidate["policy"])[name])
				}
				for _, raw := range lists {
					list := arr(raw)
					rng.Shuffle(len(list), func(i, j int) { list[i], list[j] = list[j], list[i] })
				}
				actual := key(comparableView(readSuccess(t, stateForTest(t, candidate), q)))
				if actual != baseline {
					t.Fatal("canonical output changed under permutation", i)
				}
			}
		})
	}
}

// TestReadBounds proves zero visits skip only eligible work, per-channel counters
// are independent, policy clamps are effective, and explanation caps do not
// silently truncate existence. Controls include available and unavailable sources.
func TestReadBounds(t *testing.T) {
	snapshot, q, _ := readFixture(t, "S02")
	s := stateForTest(t, snapshot)
	full := readSuccess(t, s, q)
	for _, p := range []string{"support", "oppose"} {
		if channelOf(t, full, p)["witness"] != "present" {
			t.Fatal(full)
		}
	}
	obj(q["bounds"])["roots"] = int64(0)
	zero := readSuccess(t, s, q)
	for _, p := range []string{"support", "oppose"} {
		ch := channelOf(t, zero, p)
		if ch["witness"] != "not_found" || ch["evaluation"] != "incomplete" {
			t.Fatal(ch)
		}
	}
	if !equalJSON(zero["cutoffs"], []any{"root_limit"}) {
		t.Fatal(zero)
	}
	obj(obj(obj(snapshot["policy"])["limits"])["read"])["roots"] = int64(1)
	s = stateForTest(t, snapshot)
	obj(q["bounds"])["roots"] = int64(999)
	clamped := readSuccess(t, s, q)
	obj(q["bounds"])["roots"] = int64(1)
	exact := readSuccess(t, s, q)
	if !equalJSON(comparableView(clamped), comparableView(exact)) || channelOf(t, clamped, "oppose")["witness"] != "present" {
		t.Fatal("clamp or independent channels", clamped, exact)
	}
	snapshot, q, _ = readFixture(t, "S03")
	obj(q["bounds"])["rules"] = int64(0)
	zero = readSuccess(t, stateForTest(t, snapshot), q)
	if !contains(zero["cutoffs"], "rule_limit") || channelOf(t, zero, "support")["evaluation"] != "incomplete" {
		t.Fatal(zero)
	}
	snapshot, q, _ = readFixture(t, "B13")
	obj(q["bounds"])["source_resolutions"] = int64(0)
	zero = readSuccess(t, stateForTest(t, snapshot), q)
	if !equalJSON(zero["cutoffs"], []any{"source_limit"}) {
		t.Fatal(zero)
	}
	obj(q["bounds"])["source_resolutions"] = int64(1)
	unavailable := readSuccess(t, stateForTest(t, snapshot), q)
	if !equalJSON(unavailable["cutoffs"], []any{"source_unavailable"}) {
		t.Fatal(unavailable)
	}
	for _, r := range arr(snapshot["records"]) {
		if env(r)["kind"] == "source" {
			body(r)["availability"] = "resolvable"
		}
	}
	for _, f := range arr(obj(snapshot["policy"])["source_access"]) {
		obj(f)["resolvable"] = true
	}
	available := readSuccess(t, stateForTest(t, snapshot), q)
	if channelOf(t, available, "support")["witness"] != "present" || len(arr(available["cutoffs"])) != 0 {
		t.Fatal(available)
	}
	snapshot, q, _ = readFixture(t, "S07")
	s = stateForTest(t, snapshot)
	obj(q["bounds"])["explanations"] = int64(0)
	limited := readSuccess(t, s, q)
	if obj(limited["explanation"])["reason"] != "explanation_limit" || channelOf(t, limited, "support")["evaluation"] != "complete" || channelOf(t, limited, "support")["witness"] != "present" {
		t.Fatal(limited)
	}
	q["kind"] = "recall"
	recall := readSuccess(t, s, q)
	if !equalJSON(recall["explanation"], map[string]any{"status": "complete", "paths": []any{}, "reason": nil}) {
		t.Fatal(recall)
	}
}

// TestHiddenRecordsBeforeAccounting proves hidden roots cannot spend a visible
// budget or alter success/refusal, and metadata/read/use are independent gates.
func TestHiddenRecordsBeforeAccounting(t *testing.T) {
	snapshot, q, _ := readFixture(t, "B08")
	withHidden := stateForTest(t, snapshot)
	visible := readSuccess(t, withHidden, q)
	if channelOf(t, visible, "support")["witness"] != "present" || channelOf(t, visible, "support")["evaluation"] != "complete" {
		t.Fatal(visible)
	}
	kept := []any{}
	for _, r := range arr(snapshot["records"]) {
		if env(r)["kind"] != "assessment" || env(r)["id"] == "rec:z-visible" {
			kept = append(kept, r)
		}
	}
	snapshot["records"] = kept
	withoutHidden := stateForTest(t, snapshot)
	if !equalJSON(comparableView(visible), comparableView(readSuccess(t, withoutHidden, q))) {
		t.Fatal("hidden roots changed output")
	}
	obj(q["policy"])["version"] = int64(999)
	readRefused(t, withHidden, q, PolicyMismatch)
	readRefused(t, withoutHidden, q, PolicyMismatch)
	for _, right := range []string{"read", "use", "metadata"} {
		t.Run(right, func(t *testing.T) {
			snap, query, _ := readFixture(t, "S02")
			for _, g := range arr(obj(snap["policy"])["grants"]) {
				if right == "metadata" {
					obj(g)["metadata"] = false
				} else {
					rights := []any{}
					for _, x := range arr(obj(g)["rights"]) {
						if x != right {
							rights = append(rights, x)
						}
					}
					obj(g)["rights"] = rights
				}
			}
			v := readSuccess(t, stateForTest(t, snap), query)
			if len(arr(v["items"])) != 0 || len(arr(v["cutoffs"])) != 0 || v["currentness"] != "none" {
				t.Fatal(v)
			}
		})
	}
}

// TestDirtyProjectionBoundary proves a private registered invalidation changes
// the private projection but not public bytes, budgets, review refs or global
// dirty state. Historical cuts remain unaffected; resolved causes stay resolved.
func TestDirtyProjectionBoundary(t *testing.T) {
	snapshot, q, ops := readFixture(t, "S24")
	s := stateForTest(t, snapshot)
	before := readSuccess(t, s, obj(obj(ops[0])["query"]))
	success(t, s, obj(ops[1]))
	success(t, s, obj(ops[2]))
	global := s.Snapshot()
	if len(arr(obj(global["runtime"])["dirty"])) == 0 {
		t.Fatal("positive dirty control missing")
	}
	public := readSuccess(t, s, q)
	if !equalJSON(comparableView(before), comparableView(public)) {
		t.Fatal("hidden cause changed public projection", public)
	}
	private := readSuccess(t, s, obj(obj(ops[3])["query"]))
	ch := channelOf(t, private, "support")
	if ch["evaluation"] != "incomplete" || ch["witness"] != "not_found" || !contains(private["cutoffs"], "dirty") || firstItem(t, private)["needs_review"] != true {
		t.Fatal(private)
	}
	if !equalJSON(global, s.Snapshot()) {
		t.Fatal("read cleared global dirty state")
	}
	old := copyJSON(q).(map[string]any)
	obj(old["cut"])["memory"] = int64(100)
	if !equalJSON(comparableView(before), comparableView(readSuccess(t, s, old))) {
		t.Fatal("later cause changed historical answer")
	}
	// A recomputed snapshot explicitly clears causes. Past sufficient edges alone
	// cannot recreate a private review marker from historical revisions.
	obj(global["runtime"])["dirty"] = []any{}
	obj(global["runtime"])["dirty_causes"] = []any{}
	resolved := readSuccess(t, stateForTest(t, global), obj(obj(ops[3])["query"]))
	if contains(resolved["cutoffs"], "dirty") || firstItem(t, resolved)["needs_review"] == true {
		t.Fatal("resolved causes resurrected", resolved)
	}
}

// TestFrozenFreshnessAndChanges proves equality at a horizon is stale without
// changing evidence, saved bytes are immutable, fresh views have new handles,
// and changes bindings reject another principal while hidden work stays equal.
func TestFrozenFreshnessAndChanges(t *testing.T) {
	snapshot, _, ops := readFixture(t, "P04")
	s := stateForTest(t, snapshot)
	q := obj(obj(ops[0])["query"])
	frozen, r := s.Capture(0, q)
	if r != nil {
		t.Fatal(r)
	}
	bytes := key(frozen)
	if channelOf(t, frozen, "support")["freshness"] != "fresh" {
		t.Fatal(frozen)
	}
	stale := readSuccess(t, s, obj(obj(ops[1])["query"]))
	if channelOf(t, stale, "support")["freshness"] != "stale" || channelOf(t, stale, "support")["witness"] != channelOf(t, frozen, "support")["witness"] {
		t.Fatal(stale)
	}
	if key(s.Captured(0)) != bytes || frozen["authorized_snapshot_handle"] == stale["authorized_snapshot_handle"] {
		t.Fatal("frozen bytes or fresh handle")
	}
	firstItem(t, frozen)["content"] = []any{}
	if key(s.Captured(0)) != bytes {
		t.Fatal("caller alias changed capture")
	}
	query := copyJSON(q).(map[string]any)
	query["kind"] = "changes"
	query["since"] = int64(0)
	unchanged := readSuccess(t, s, query)
	if obj(unchanged["changes"])["state"] != "no_change" {
		t.Fatal(unchanged)
	}
	if _, r := s.SeedLoad(s.policy()["owner"].(string), 9000); r != nil {
		t.Fatal(r)
	}
	if obj(readSuccess(t, s, query)["changes"])["state"] != "no_change" {
		t.Fatal("hidden work changed cursor")
	}
	query["now"] = obj(obj(ops[1])["query"])["now"]
	changed := readSuccess(t, s, query)
	if obj(changed["changes"])["state"] != "changed" || len(arr(obj(changed["changes"])["refs"])) != 1 {
		t.Fatal(changed)
	}
	query["principal"] = "principal:other"
	readRefused(t, s, query, NotAuthorized)
}

// TestReadValidationOrder proves public shape/configuration and policy checks
// precede availability and restore gates. Paired valid queries return views;
// failed reads never mint success payloads or mutate the full snapshot.
func TestReadValidationOrder(t *testing.T) {
	snapshot, q, _ := readFixture(t, "S01")
	s := stateForTest(t, snapshot)
	readSuccess(t, s, q)
	s.policy()["availability_disclosure"] = "coarse_unavailable"
	s.policy()["public_availability"] = "degraded"
	obj(s.runtime()["restore"])["status"] = "fenced"
	bad := copyJSON(q).(map[string]any)
	bad["extra"] = true
	readRefused(t, s, bad, InvalidShape)
	bad = copyJSON(q).(map[string]any)
	obj(bad["bounds"])["roots"] = int64(-1)
	obj(bad["policy"])["version"] = int64(999)
	readRefused(t, s, bad, InvalidShape)
	bad = copyJSON(q).(map[string]any)
	obj(obj(bad["scope"])["schema"])["version"] = int64(999)
	readRefused(t, s, bad, UnknownSchema)
	bad = copyJSON(q).(map[string]any)
	obj(bad["projection_rule"])["version"] = int64(999)
	readRefused(t, s, bad, UnknownRule)
	bad = copyJSON(q).(map[string]any)
	obj(bad["policy"])["version"] = int64(999)
	readRefused(t, s, bad, PolicyMismatch)
	readRefused(t, s, q, Unavailable)
	s.policy()["public_availability"] = "available"
	readRefused(t, s, q, ErasureFenced)
	obj(s.runtime()["restore"])["status"] = "open"
	for _, mutate := range []func(map[string]any){func(q map[string]any) { q["now"] = "2026-02-30T00:00:00Z" }, func(q map[string]any) { obj(q["cut"])["memory"] = int64(99) }, func(q map[string]any) {
		obj(q["cut"])["sources"] = []any{map[string]any{"owner": "system:other", "revision": "r1"}}
	}} {
		bad = copyJSON(q).(map[string]any)
		mutate(bad)
		readRefused(t, s, bad, InvalidTime)
	}
	readSuccess(t, s, q)
}

// TestReadConfigurationAmbiguity rejects order-sensitive policy/configuration
// duplicates with their intended diagnostic and no partially loaded state.
func TestReadConfigurationAmbiguity(t *testing.T) {
	for _, tc := range []struct {
		name, id string
		change   func(map[string]any)
		code     RefusalCode
	}{
		{"coverage", "S30", func(m map[string]any) {
			p := obj(m["policy"])
			p["coverage"] = append(arr(p["coverage"]), copyJSON(arr(p["coverage"])[0]))
		}, InvalidReference},
		{"projection", "S01", func(m map[string]any) {
			m["projection_rules"] = append(arr(m["projection_rules"]), copyJSON(arr(m["projection_rules"])[0]))
		}, InvalidDomainValue},
		{"non audience exclusion", "S01", func(m map[string]any) {
			obj(arr(m["projection_rules"])[0])["excluded_refs"] = []any{ref(arr(m["records"])[0])}
		}, InvalidDomainValue},
		{"source access", "B13", func(m map[string]any) {
			p := obj(m["policy"])
			p["source_access"] = append(arr(p["source_access"]), copyJSON(arr(p["source_access"])[0]))
		}, InvalidReference},
		{"alias key", "P09", func(m map[string]any) {
			p := obj(m["policy"])
			p["handles"] = append(arr(p["handles"]), copyJSON(arr(p["handles"])[0]))
		}, InvalidReference},
	} {
		t.Run(tc.name, func(t *testing.T) {
			snapshot, _, _ := readFixture(t, tc.id)
			stateForTest(t, snapshot)
			tc.change(snapshot)
			s, r := NewState(snapshot, packageSchemas(t), mintForTest())
			if s != nil || r == nil || r.Code != tc.code {
				t.Fatal(s, r)
			}
		})
	}
}

// TestAvailabilityAndHandleContract proves only an owner under a predeclared
// coarse policy can change availability. Bad/reused adapter handles fail closed.
func TestAvailabilityAndHandleContract(t *testing.T) {
	snapshot, q, ops := readFixture(t, "S27")
	s := stateForTest(t, snapshot)
	readSuccess(t, s, q)
	op := obj(ops[3])
	bad := copyJSON(op).(map[string]any)
	bad["actor"] = "principal:other"
	before := s.Snapshot()
	if v, r := s.SetAvailability(bad); v != nil || r == nil || r.Code != NotAuthorized || !equalJSON(before, s.Snapshot()) {
		t.Fatal(v, r)
	}
	s.policy()["availability_disclosure"] = "none"
	before = s.Snapshot()
	if v, r := s.SetAvailability(op); v != nil || r == nil || r.Code != NotAuthorized || !equalJSON(before, s.Snapshot()) {
		t.Fatal(v, r)
	}
	s.policy()["availability_disclosure"] = "coarse_unavailable"
	if _, r := s.SetAvailability(op); r != nil {
		t.Fatal(r)
	}
	readRefused(t, s, q, Unavailable)
	op["state"] = "available"
	if _, r := s.SetAvailability(op); r != nil {
		t.Fatal(r)
	}
	readSuccess(t, s, q)
	s.mint = func() (string, error) { return "@h1", nil }
	readRefused(t, s, q, Unavailable)
	s.mint = func() (string, error) { return "", fmt.Errorf("entropy unavailable") }
	readRefused(t, s, q, Unavailable)
	counter := mintForTest()
	s.mint = counter // its first handle was already issued
	readRefused(t, s, q, Unavailable)
}

// TestTypedReadInterface proves Recall/Explain/Changes use the actual evaluator
// and Context.Actor supplies the authenticated principal rather than trusting a
// caller-supplied principal override. Context pins and argument maps stay intact.
func TestTypedReadInterface(t *testing.T) {
	snapshot, q, _ := readFixture(t, "S02")
	s := stateForTest(t, snapshot)
	ctx := Context{Actor: q["principal"].(string), ReadQuery: Query(q)}
	before := key(q)
	var k Kernel = s
	v, r := k.Recall(ctx, Query(q))
	if r != nil || channelOf(t, map[string]any(v), "support")["witness"] != "present" {
		t.Fatal(v, r)
	}
	target := obj(arr(obj(q["scope"])["targets"])[0])
	ex, r := k.Explain(ctx, VersionRef(target), Bounds(obj(q["bounds"])))
	if r != nil || len(arr(obj(ex["explanation"])["paths"])) != 2 {
		t.Fatal(ex, r)
	}
	if _, r := s.Capture(0, q); r != nil {
		t.Fatal(r)
	}
	changes, r := k.Changes(ctx, Cursor{"since": int64(0)}, Bounds(obj(q["bounds"])))
	if r != nil || obj(changes["changes"])["state"] != "no_change" || key(q) != before {
		t.Fatal(changes, r)
	}
	ctx.Actor = "principal:no-grants"
	hidden, r := k.Recall(ctx, Query(q))
	if r != nil || len(arr(hidden["items"])) != 0 {
		t.Fatal("query principal impersonation", hidden, r)
	}
}

// TestThreeConflictOutcomes proves CAS refuses without mutation, incomparable
// canonical decisions stay admitted as ambiguous items, and signed conflict
// retains both exact-assertion witnesses without conflating those outcomes.
func TestThreeConflictOutcomes(t *testing.T) {
	snapshot, q, _ := readFixture(t, "S02")
	evidence := readSuccess(t, stateForTest(t, snapshot), q)
	if evidence["currentness"] != "current" || channelOf(t, evidence, "support")["witness"] != "present" || channelOf(t, evidence, "oppose")["witness"] != "present" {
		t.Fatal(evidence)
	}
	snapshot, q, _ = readFixture(t, "S28")
	ambiguous := readSuccess(t, stateForTest(t, snapshot), q)
	if ambiguous["currentness"] != "ambiguous_current" || len(arr(ambiguous["items"])) != 2 {
		t.Fatal(ambiguous)
	}
	for _, item := range arr(ambiguous["items"]) {
		if obj(obj(item)["oppose"])["witness"] != "not_found" {
			t.Fatal("ambiguity fabricated opposition", item)
		}
	}
	snapshot, q, ops := readFixture(t, "P14")
	s := stateForTest(t, snapshot)
	success(t, s, obj(ops[0]))
	refusalUnchanged(t, s, obj(ops[2]), VersionConflict)
	current := readSuccess(t, s, q)
	if current["currentness"] != "current" || channelOf(t, current, "oppose")["witness"] != "not_found" || firstItem(t, current)["needs_review"] != false {
		t.Fatal("write collision became evidence", current)
	}
}

// TestSourceAndPremiseQualityNeighbors proves source state aggregates complete
// AND paths by weakest premise and OR alternatives by strongest path; a clean
// root wins over a tainted rule without deleting either polarity witness.
func TestSourceAndPremiseQualityNeighbors(t *testing.T) {
	snapshot, _, ops := readFixture(t, "S32")
	s := stateForTest(t, snapshot)
	prior := readSuccess(t, s, obj(obj(ops[1])["query"]))
	if channelOf(t, prior, "support")["source_state"] != "prior_assessment_only" {
		t.Fatal(prior)
	}
	attestationQuery := copyJSON(obj(obj(ops[0])["query"])).(map[string]any)
	obj(attestationQuery["scope"])["targets"] = []any{map[string]any{"id": "rec:attested", "version": int64(1)}}
	attestation := readSuccess(t, s, attestationQuery)
	if channelOf(t, attestation, "support")["source_state"] != "independent_attestation" {
		t.Fatal(attestation)
	}
	or := readSuccess(t, s, obj(obj(ops[2])["query"]))
	if channelOf(t, or, "support")["source_state"] != "resolvable_now" {
		t.Fatal(or)
	}
	snapshot, q, _ := readFixture(t, "S03")
	tainted := readSuccess(t, stateForTest(t, snapshot), q)
	if channelOf(t, tainted, "support")["premise_quality"] != "conflicted_premises_only" {
		t.Fatal(tainted)
	}
	// Retarget an independently admitted root and its exact pin to the conclusion.
	for _, r := range arr(snapshot["records"]) {
		if env(r)["kind"] == "assessment" && obj(body(r)["target"])["polarity"] == "support" {
			target := arr(obj(q["scope"])["targets"])[0]
			obj(body(r)["target"])["assertion"] = copyJSON(target)
			obj(body(r)["pins"])["subject"] = copyJSON(target)
			break
		}
	}
	clean := readSuccess(t, stateForTest(t, snapshot), q)
	if channelOf(t, clean, "support")["premise_quality"] != "clean_path" {
		t.Fatal(clean)
	}
	obj(q["bounds"])["roots"] = int64(0)
	obj(q["bounds"])["rules"] = int64(0)
	bounded := readSuccess(t, stateForTest(t, snapshot), q)
	if !equalJSON(bounded["cutoffs"], []any{"root_limit", "rule_limit"}) {
		t.Fatal("cutoffs are not explicit and sorted", bounded)
	}

}

// TestChangesIgnoresProofRendering proves selecting explain instead of recall
// does not itself constitute a content/qualification/authorization change.
func TestChangesIgnoresProofRendering(t *testing.T) {
	snapshot, q, _ := readFixture(t, "S02")
	s := stateForTest(t, snapshot)
	q["kind"] = "explain"
	v, r := s.Capture(0, q)
	if r != nil || len(arr(obj(v["explanation"])["paths"])) == 0 {
		t.Fatal(v, r)
	}
	q["kind"] = "changes"
	q["since"] = int64(0)
	changed := readSuccess(t, s, q)
	if obj(changed["changes"])["state"] != "no_change" {
		t.Fatal(changed)
	}
}

// TestCivilFreshnessArithmetic proves calendar boundaries and leap rules are
// computed from supplied UTC seconds; overflow is rejected without clock IO.
func TestCivilFreshnessArithmetic(t *testing.T) {
	for _, tc := range []struct {
		at      string
		seconds int64
		want    any
	}{
		{"2024-02-28T23:59:59Z", 1, "2024-02-29T00:00:00Z"},
		{"2100-02-28T23:59:59Z", 1, "2100-03-01T00:00:00Z"},
		{"2026-12-31T23:59:59Z", 1, "2027-01-01T00:00:00Z"},
		{"9999-12-31T23:59:59Z", 1, nil},
	} {
		if got := addSeconds(tc.at, tc.seconds); got != tc.want {
			t.Fatal(tc, got)
		}
	}
}

// TestHiddenDependenciesAreFree proves inaccessible premises, certificates and
// named sources filter whole candidates before budget accounting or public gaps.
func TestHiddenDependenciesAreFree(t *testing.T) {
	for _, tc := range []struct{ id, hidden, budget, cutoff string }{
		{"S03", "rec:a", "rules", "rule_limit"},
		{"S03", "cert:j", "rules", "rule_limit"},
		{"B13", "rec:s", "roots", "root_limit"},
	} {
		t.Run(tc.id+"/"+tc.hidden, func(t *testing.T) {
			snapshot, q, _ := readFixture(t, tc.id)
			if tc.hidden == "cert:j" {
				for _, r := range arr(snapshot["records"]) {
					if env(r)["kind"] == "justification" && body(r)["role"] == "sufficient_support" {
						tc.hidden = obj(body(r)["check"])["id"].(string)
						break
					}
				}
			}
			obj(q["bounds"])[tc.budget] = int64(0)
			visible := readSuccess(t, stateForTest(t, snapshot), q)
			if !contains(visible["cutoffs"], tc.cutoff) {
				t.Fatal("positive budget control", visible)
			}
			ids := []any{}
			found := false
			for _, r := range arr(snapshot["records"]) {
				if env(r)["id"] == tc.hidden {
					found = true
				} else {
					ids = append(ids, env(r)["id"])
				}
			}
			if !found {
				t.Fatal("plant not applied", tc.hidden)
			}
			for _, grant := range arr(obj(snapshot["policy"])["grants"]) {
				obj(grant)["records"] = set(ids)
			}
			hidden := readSuccess(t, stateForTest(t, snapshot), q)
			if channelOf(t, hidden, "support")["witness"] != "not_found" || channelOf(t, hidden, "support")["evaluation"] != "complete" || len(arr(hidden["cutoffs"])) != 0 {
				t.Fatal("hidden dependency spent work or leaked gap", hidden)
			}
		})
	}
}

// TestReadOutputOwnership proves visible source metadata does not expose mutable
// aliases into the state, even after capture or mutation of caller query maps.
func TestReadOutputOwnership(t *testing.T) {
	snapshot, q, _ := readFixture(t, "B13")
	s := stateForTest(t, snapshot)
	before := key(s.Snapshot())
	v := readSuccess(t, s, q)
	sources := arr(firstItem(t, v)["source_refs"])
	if len(sources) != 1 {
		t.Fatal("source control missing")
	}
	obj(sources[0])["id"] = "mutated-output"
	if key(s.Snapshot()) != before {
		t.Fatal("view leaked state alias")
	}
	frozen, r := s.Capture(0, q)
	if r != nil {
		t.Fatal(r)
	}
	canonical := key(frozen)
	obj(q["scope"])["subject"] = "mutated-query"
	if key(s.Captured(0)) != canonical {
		t.Fatal("capture leaked query alias")
	}
}

// TestReadExpiredAssessmentNeighbors proves policy/environment mismatch, expiry,
// non-pass result and wrong context cannot qualify a previously passing root.
// A valid root remains a nearby positive control for each independent mutation.
func TestReadExpiredAssessmentNeighbors(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(any, map[string]any)
	}{
		{"policy pin", func(r any, q map[string]any) { obj(obj(body(r)["pins"])["policy"])["version"] = int64(2) }},
		{"environment pin", func(r any, q map[string]any) { obj(obj(body(r)["pins"])["environment"])["version"] = int64(2) }},
		{"expiry equality", func(r any, q map[string]any) { body(r)["usable_until"] = q["now"] }},
		{"fail", func(r any, q map[string]any) { body(r)["result"] = "fail" }},
		{"indeterminate", func(r any, q map[string]any) { body(r)["result"] = "indeterminate" }},
		{"simulation", func(r any, q map[string]any) { env(r)["context"] = "simulated" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			snapshot, q, _ := readFixture(t, "S02")
			good := readSuccess(t, stateForTest(t, snapshot), q)
			if channelOf(t, good, "support")["witness"] != "present" {
				t.Fatal(good)
			}
			applied := false
			for _, r := range arr(snapshot["records"]) {
				if env(r)["kind"] == "assessment" && obj(body(r)["target"])["polarity"] == "support" {
					tc.mutate(r, q)
					applied = true
				}
			}
			if !applied {
				t.Fatal("mutation not applied")
			}
			rejected := readSuccess(t, stateForTest(t, snapshot), q)
			if channelOf(t, rejected, "support")["witness"] != "not_found" || channelOf(t, rejected, "oppose")["witness"] != "present" {
				t.Fatal(rejected)
			}
		})
	}
}

// TestConcurrentReadAndWrite proves a historical read remains a complete old-cut
// answer while one writer commits and concurrent retries replay the same receipt.
// The race detector also checks the shared state and injected handle generator.
func TestConcurrentReadAndWrite(t *testing.T) {
	snapshot, q, ops := readFixture(t, "S14")
	s := stateForTest(t, snapshot)
	obj(q["cut"])["memory"] = int64(100)
	expected := key(comparableView(readSuccess(t, s, q)))
	var wg sync.WaitGroup
	errs := make(chan string, 64)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 8; j++ {
				v, r := s.Read(q)
				if r != nil || key(comparableView(v)) != expected {
					errs <- fmt.Sprint("historical read", v, r)
					return
				}
			}
		}()
	}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, r := s.Write(obj(ops[0])); r != nil {
				errs <- r.Error()
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
	if s.runtime()["memory_cut"] != int64(101) || len(arr(s.runtime()["idempotency"])) != 1 {
		t.Fatal("retry duplicated commit")
	}
}

// TestCanonicalReadReferenceSets proves JSON reference sets use canonical JSON
// order (version 10 before version 2), independently of numeric walk ordering.
func TestCanonicalReadReferenceSets(t *testing.T) {
	refs := []any{map[string]any{"id": "assessment:x", "version": int64(2)}, map[string]any{"id": "assessment:x", "version": int64(10)}}
	proof := evaluation{paths: []evidencePath{{refs: refs}}}.proofs()
	if !equalJSON(arr(proof[0]), set(refs)) {
		t.Fatal("proof reference set not canonical", proof)
	}
	snapshot, q, _ := readFixture(t, "B13")
	var source any
	for _, r := range arr(snapshot["records"]) {
		if env(r)["kind"] == "source" {
			source = r
			break
		}
	}
	if source == nil {
		t.Fatal("source control missing")
	}
	additions := []any{}
	for i, version := range []int64{2, 10} {
		clone := copyJSON(source)
		env(clone)["version"] = version
		obj(env(clone)["recorded"])["sequence"] = int64(81 + i)
		snapshot["records"] = append(arr(snapshot["records"]), clone)
		additions = append(additions, ref(clone))
		p := obj(snapshot["policy"])
		f := copyJSON(obj(arr(p["lineage_facts"])[0])).(map[string]any)
		f["output"] = ref(clone)
		f["inputs"] = []any{}
		f["kind"] = "direct"
		f["complete"] = true
		p["lineage_facts"] = append(arr(p["lineage_facts"]), f)
	}
	for _, r := range arr(snapshot["records"]) {
		if env(r)["kind"] == "assessment" {
			body(r)["sources"] = set(append(arr(body(r)["sources"]), additions...))
		}
	}
	view := readSuccess(t, stateForTest(t, snapshot), q)
	got := firstItem(t, view)["source_refs"]
	if !equalJSON(got, set(append([]any{ref(source)}, additions...))) {
		t.Fatal("source reference set not canonical", got)
	}
}

// TestRepeatedAndPremisesStayFinite proves 32 repeated references with two root
// alternatives produce three unique proof sets, not 2^32 duplicate paths, while
// preserving witness existence, origin union, completeness and premise conflict.
func TestRepeatedAndPremisesStayFinite(t *testing.T) {
	snapshot, q, _ := readFixture(t, "S03")
	q["kind"] = "explain"
	var root, rule any
	for _, r := range arr(snapshot["records"]) {
		if env(r)["kind"] == "assessment" && obj(body(r)["target"])["polarity"] == "support" {
			root = r
		}
		if env(r)["kind"] == "justification" && body(r)["role"] == "sufficient_support" {
			rule = r
		}
	}
	if root == nil || rule == nil {
		t.Fatal("fixture control missing")
	}
	another := copyJSON(root)
	env(another)["id"] = "assessment:alternative"
	obj(env(another)["recorded"])["sequence"] = int64(91)
	body(another)["origin"] = "origin:alternative"
	snapshot["records"] = append(arr(snapshot["records"]), another)
	p := obj(snapshot["policy"])
	fact := copyJSON(obj(arr(p["lineage_facts"])[0])).(map[string]any)
	fact["output"] = ref(another)
	fact["inputs"] = []any{}
	fact["complete"] = true
	fact["kind"] = "direct"
	p["lineage_facts"] = append(arr(p["lineage_facts"]), fact)
	premise := arr(body(rule)["premises"])[0]
	body(rule)["premises"] = []any{}
	for i := 0; i < 32; i++ {
		body(rule)["premises"] = append(arr(body(rule)["premises"]), copyJSON(premise))
	}
	view := readSuccess(t, stateForTest(t, snapshot), q)
	ch := channelOf(t, view, "support")
	if ch["witness"] != "present" || ch["evaluation"] != "complete" || ch["independent_root_count"] != int64(2) || ch["premise_quality"] != "conflicted_premises_only" || len(arr(obj(view["explanation"])["paths"])) != 3 {
		t.Fatal(view)
	}
}

// TestOwnerExclusionPreservesPremises proves an excluded display item can remain
// an authorized premise, while excluding the requested conclusion removes its
// item and metadata without manufacturing opposition or a cutoff.
func TestOwnerExclusionPreservesPremises(t *testing.T) {
	snapshot, q, _ := readFixture(t, "S03")
	projection := obj(arr(snapshot["projection_rules"])[0])
	projection["family"] = "audience_projection"
	projection["audience"] = q["audience"]
	projection["purpose"] = q["purpose"]
	p := obj(snapshot["policy"])
	p["handles"] = []any{map[string]any{"subject": obj(q["scope"])["subject"], "space": obj(q["scope"])["space"], "audience": q["audience"], "handle": "person:public"}}
	s := stateForTest(t, snapshot)
	control := readSuccess(t, s, q)
	if channelOf(t, control, "support")["witness"] != "present" {
		t.Fatal(control)
	}
	excluded := copyJSON(projection).(map[string]any)
	excluded["version"] = int64(2)
	excluded["excluded_refs"] = []any{map[string]any{"id": "rec:a", "version": int64(1)}}
	s.snapshot["projection_rules"] = append(arr(s.snapshot["projection_rules"]), excluded)
	obj(q["projection_rule"])["version"] = int64(2)
	premise := readSuccess(t, s, q)
	if !equalJSON(channelOf(t, control, "support")["evidence_qualification"], channelOf(t, premise, "support")["evidence_qualification"]) || channelOf(t, premise, "support")["witness"] != "present" {
		t.Fatal("exclusion removed premise", premise)
	}
	hidden := copyJSON(excluded).(map[string]any)
	hidden["version"] = int64(3)
	hidden["excluded_refs"] = copyJSON(obj(q["scope"])["targets"])
	s.snapshot["projection_rules"] = append(arr(s.snapshot["projection_rules"]), hidden)
	obj(q["projection_rule"])["version"] = int64(3)
	absent := readSuccess(t, s, q)
	if len(arr(absent["items"])) != 0 || len(arr(absent["historical"])) != 0 || len(arr(absent["review_required"])) != 0 || len(arr(absent["cutoffs"])) != 0 {
		t.Fatal(absent)
	}
}

// TestRepresentativeAudienceAlias proves a representative remains distinct from
// the issuer and requires its own exact alias before computation/handle minting.
func TestRepresentativeAudienceAlias(t *testing.T) {
	snapshot, q, ops := readFixture(t, "P10")
	s := stateForTest(t, snapshot)
	success(t, s, obj(ops[0]))
	projection := obj(arr(s.snapshot["projection_rules"])[0])
	projection["family"] = "audience_projection"
	projection["audience"] = q["audience"]
	projection["purpose"] = q["purpose"]
	var assertion any
	for _, r := range arr(s.snapshot["records"]) {
		if env(r)["kind"] == "assertion" && env(r)["issuer"] != env(r)["submitter"] {
			assertion = r
			break
		}
	}
	if assertion == nil {
		t.Fatal("representative control missing")
	}
	aliases := []any{}
	for _, principal := range []any{env(assertion)["issuer"], env(assertion)["submitter"]} {
		aliases = append(aliases, map[string]any{"subject": principal, "space": env(assertion)["space"], "audience": q["audience"], "handle": fmt.Sprint("alias:", len(aliases))})
	}
	s.policy()["handles"] = aliases
	v := readSuccess(t, s, q)
	item := firstItem(t, v)
	if item["issuer"] != "alias:0" || item["submitter"] != "alias:1" || item["subject"] != "alias:0" || obj(item["perspective"])["principal"] != "alias:0" || item["ref"] != nil || item["representation_ref"] != nil {
		t.Fatal(v)
	}
	s.policy()["handles"] = aliases[:1]
	s.mint = func() (string, error) { t.Fatal("missing alias reached handle minting"); return "", nil }
	readRefused(t, s, q, NotAuthorized)
}
