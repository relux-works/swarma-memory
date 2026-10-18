package kernel

import (
	"fmt"
	"testing"
)

// TestReleaseAssessmentRevisions proves admitted withdrawal, replacement and
// correction of either required owner's evidence close fresh public reads and
// prepared delivery, including reads at the old cut. Challenges preserve release.
// Private revision labels cannot hide the authority change from public reads.
func TestReleaseAssessmentRevisions(t *testing.T) {
	for owner := 0; owner < 2; owner++ {
		for _, relation := range []string{"withdraw", "replace", "correct", "challenge"} {
			t.Run(fmt.Sprintf("owner%d/%s", owner, relation), func(t *testing.T) {
				snapshot, _, ops := readFixture(t, "P05")
				admit := obj(ops[1])
				target := arr(admit["assessments"])[owner]
				_, templates := writeFixture(t, "S17")
				revise := obj(templates[0])
				revise["context"] = copyJSON(admit["context"])
				obj(obj(revise["context"])["retention_context"])["audience"] = "aud:private"
				revise["idempotency_key"] = "key:revise-release"
				revision := revise["revision"]
				obj(revision)["envelope"] = copyJSON(env(target))
				env(revision)["id"], env(revision)["kind"] = "rec:revise-release", "revision"
				obj(env(revision)["disclosure"])["audiences"] = []any{"aud:private"}
				b := body(revision)
				b["relation"], b["target"], b["replacement"] = relation, ref(target), nil
				revise["expected_version"], revise["replacement"] = ref(target), nil
				if relation == "replace" || relation == "correct" {
					replacement := copyJSON(target)
					env(replacement)["version"] = int64(2)
					revise["replacement"], b["replacement"] = replacement, ref(replacement)
					authorizeProposal(snapshot, replacement)
				}
				authorizeProposal(snapshot, revision)
				for _, raw := range arr(obj(snapshot["policy"])["representations"]) {
					m := obj(raw)
					m["relations"] = set(append(arr(m["relations"]), relation))
				}
				s := stateForTest(t, snapshot)
				success(t, s, admit)
				q := obj(obj(ops[2])["query"])
				firstItem(t, readSuccess(t, s, q))
				v, r := s.Capture(2, q)
				if r != nil {
					t.Fatal(r)
				}
				frozen := key(v)
				success(t, s, obj(ops[3]))
				success(t, s, revise)
				stateForTest(t, s.Snapshot())
				if key(s.Captured(2)) != frozen {
					t.Fatal("revision rewrote frozen bytes")
				}
				index := recordIndex(arr(s.snapshot["records"]))
				if !equalJSON(body(index[refKey(ref(target))]), body(target)) {
					t.Fatal("revision changed immutable assessment body")
				}
				for _, raw := range arr(s.policy()["declassification_decisions"]) {
					if obj(raw)["active"] != true {
						t.Fatal("probe must leave owner decisions active")
					}
				}
				for _, cut := range []any{obj(q["cut"])["memory"], s.runtime()["memory_cut"]} {
					query := copyJSON(q).(map[string]any)
					obj(query["cut"])["memory"] = cut
					view := readSuccess(t, s, query)
					if relation == "challenge" {
						firstItem(t, view)
					} else if len(arr(view["items"])) != 0 {
						t.Error("inactive exact assessment still authorizes public read", cut)
					}
				}
				if relation == "challenge" {
					success(t, s, obj(ops[3]))
				} else {
					refusalUnchanged(t, s, obj(ops[3]), DisclosureRevoked)
				}
				output := index[refKey(ref(admit["output"]))]
				if !s.disclosureAllows(output, "aud:private", "purpose:read", q["now"], index, map[string]bool{}) {
					t.Fatal("revision removed ordinary private access")
				}
				if replacement := revise["replacement"]; replacement != nil {
					// The new assessment keeps valid release pins and is active, but
					// cannot silently replace the output's exact version-1 citation.
					candidate := copyJSON(output)
					assessments := []any{}
					refs := []any{}
					for i, a := range arr(admit["assessments"]) {
						if i == owner {
							a = replacement
						}
						assessments = append(assessments, index[refKey(ref(a))])
						refs = append(refs, ref(a))
					}
					obj(env(candidate)["disclosure"])["declassification"] = set(refs)
					if !s.releaseValid(candidate, assessments, index, q["now"]) {
						t.Fatal("active replacement with exact updated citation is invalid")
					}
				}
			})
		}
	}
}

// TestDeclassificationPins proves a matching multi-owner release commits in
// proposal order; changed pins, missing owners and unknown lineage refuse
// atomically rather than turning release evidence into world evidence.
func TestDeclassificationPins(t *testing.T) {
	snapshot, _, ops := readFixture(t, "P05")
	op := obj(ops[1])
	s := stateForTest(t, snapshot)
	success(t, s, op)
	records := arr(s.Snapshot()["records"])
	batch := batchProposals(op)
	for i, r := range records[len(records)-len(batch):] {
		if !equalJSON(ref(r), ref(batch[i])) || obj(env(r)["recorded"])["sequence"] != int64(101+i) || env(r)["submitter"] != obj(op["context"])["actor"] {
			t.Fatal("declassification transaction order/attribution", r)
		}
	}
	publicQuery := obj(obj(ops[2])["query"])
	view := readSuccess(t, s, publicQuery)
	if firstItem(t, view)["ref"] != nil || channelOf(t, view, "support")["witness"] != "not_found" {
		t.Fatal("release exposed internal identity or became a root", view)
	}
	for _, field := range []string{"output_digest", "audience", "purpose", "transformation", "output_schema", "inputs"} {
		t.Run(field, func(t *testing.T) {
			candidate := copyJSON(op).(map[string]any)
			pins := obj(body(arr(candidate["assessments"])[0])["declassification"])
			switch field {
			case "output_digest":
				pins[field] = "0000000000000000000000000000000000000000000000000000000000000000"
			case "transformation", "output_schema":
				obj(pins[field])["version"] = int64(2)
			case "inputs":
				pins[field] = []any{}
			default:
				pins[field] = "different:release-context"
			}
			refusalUnchanged(t, stateForTest(t, snapshot), candidate, DeclassificationInvalid)
		})
	}
	for _, field := range []string{"policy", "environment"} {
		candidate := copyJSON(op).(map[string]any)
		obj(obj(body(arr(candidate["assessments"])[0])["pins"])[field])["version"] = int64(2)
		refusalUnchanged(t, stateForTest(t, snapshot), candidate, DeclassificationInvalid)
	}
	// Even mutually matching owner pins cannot authenticate the wrong body digest.
	candidateSnapshot := copyJSON(snapshot).(map[string]any)
	candidate := copyJSON(op).(map[string]any)
	for _, a := range arr(candidate["assessments"]) {
		obj(body(a)["declassification"])["output_digest"] = "bad:digest"
	}
	for _, d := range arr(obj(candidateSnapshot["policy"])["declassification_decisions"]) {
		obj(obj(d)["pins"])["output_digest"] = "bad:digest"
	}
	refusalUnchanged(t, stateForTest(t, candidateSnapshot), candidate, DeclassificationInvalid)
	refusalUnchanged(t, stateForTest(t, snapshot), obj(ops[0]), DeclassificationInvalid)
	candidateSnapshot = copyJSON(snapshot).(map[string]any)
	for _, raw := range arr(obj(candidateSnapshot["policy"])["lineage_facts"]) {
		if equalJSON(obj(raw)["output"], ref(op["output"])) {
			obj(raw)["complete"] = false
		}
	}
	refusalUnchanged(t, stateForTest(t, candidateSnapshot), op, DeclassificationInvalid)
	candidate = copyJSON(op).(map[string]any)
	body(arr(candidate["assessments"])[0])["executor"] = "model"
	refusalUnchanged(t, stateForTest(t, snapshot), candidate, AssessmentKindInvalid)
}

// TestReleaseRevocationAndExactContext proves owner revocation filters new
// reads and blocks prepared delivery without rewriting frozen bytes. A live
// release widens only its pinned audience/purpose; private access remains valid.
func TestReleaseRevocationAndExactContext(t *testing.T) {
	snapshot, _, ops := readFixture(t, "P05")
	s := stateForTest(t, snapshot)
	success(t, s, obj(ops[1]))
	q := obj(obj(ops[2])["query"])
	v, r := s.Capture(2, q)
	if r != nil {
		t.Fatal(r)
	}
	frozen := key(v)
	success(t, s, obj(ops[3]))
	index := recordIndex(arr(s.snapshot["records"]))
	output := index[refKey(ref(obj(ops[1])["output"]))]
	if s.disclosureAllows(output, q["audience"], "purpose:read", q["now"], index, map[string]bool{}) || !s.disclosureAllows(output, "aud:private", "purpose:read", q["now"], index, map[string]bool{}) {
		t.Fatal("release widened another context or removed private access")
	}
	wrong := copyJSON(obj(ops[4])).(map[string]any)
	wrong["actor"] = s.policy()["owner"]
	refusalUnchanged(t, s, wrong, NotAuthorized)
	cut := s.runtime()["memory_cut"]
	success(t, s, obj(ops[4]))
	if s.runtime()["memory_cut"] != cut || key(s.Captured(2)) != frozen {
		t.Fatal("revocation rewrote semantic history")
	}
	if len(arr(readSuccess(t, s, q)["items"])) != 0 {
		t.Fatal("revoked release still visible")
	}
	refusalUnchanged(t, s, obj(ops[5]), DisclosureRevoked)
}

// TestReleaseNeedsCurrentEvidence proves erasing release evidence removes its
// authority even while the owner's decision remains active; the unfenced pair
// admits the exact same output and prepared delivery.
func TestReleaseNeedsCurrentEvidence(t *testing.T) {
	snapshot, _, ops := readFixture(t, "P05")
	s := stateForTest(t, snapshot)
	success(t, s, obj(ops[1]))
	q := obj(obj(ops[2])["query"])
	if _, r := s.Capture(2, q); r != nil {
		t.Fatal(r)
	}
	success(t, s, obj(ops[3]))
	erase := map[string]any{"op": "erase", "actor": s.policy()["owner"], "at": q["now"], "idempotency_key": "key:release-evidence", "targets": []any{ref(arr(obj(ops[1])["assessments"])[0])}, "boundary": []any{}, "receipt_context": map[string]any{"audience": "aud:private", "purpose": "purpose:read"}}
	success(t, s, erase)
	if len(arr(readSuccess(t, s, q)["items"])) != 0 {
		t.Fatal("fenced evidence still grants release")
	}
	refusalUnchanged(t, s, obj(ops[3]), DisclosureRevoked)
}

// TestDisclosureConfigurationKeys proves duplicate/empty owner assignments and
// duplicate decisions cannot choose authority by array order; valid controls load.
func TestDisclosureConfigurationKeys(t *testing.T) {
	for _, field := range []string{"constraint_owners", "declassification_decisions"} {
		snapshot, _, _ := readFixture(t, "P05")
		stateForTest(t, snapshot)
		policy := obj(snapshot["policy"])
		policy[field] = append(arr(policy[field]), copyJSON(arr(policy[field])[0]))
		if _, r := NewState(snapshot, packageSchemas(t), mintForTest()); r == nil || r.Code != InvalidReference {
			t.Fatal("duplicate key accepted", field, r)
		}
	}
	snapshot, _, _ := readFixture(t, "P05")
	obj(arr(obj(snapshot["policy"])["constraint_owners"])[0])["owners"] = []any{}
	if _, r := NewState(snapshot, packageSchemas(t), mintForTest()); r == nil || r.Code != InvalidReference {
		t.Fatal("empty constraint owners accepted", r)
	}
}

// TestPublicationCurrentnessControls proves checked imports retain their issuer
// origins; future/unconfirmed checks are last_received, known replacement is
// historical, and a prepared import cannot be delivered after replacement.
func TestPublicationCurrentnessControls(t *testing.T) {
	snapshot, q, _ := readFixture(t, "P07")
	if firstItem(t, readSuccess(t, stateForTest(t, snapshot), q))["currentness"] != "current" {
		t.Fatal("missing checked import control")
	}
	for _, status := range []string{"unverified", "future", "replaced"} {
		candidate := copyJSON(snapshot).(map[string]any)
		for _, raw := range arr(obj(candidate["policy"])["imports"]) {
			m := obj(raw)
			if status == "future" {
				m["checked_at"] = "2026-11-01T00:00:00Z"
			} else {
				m["status"] = status
			}
		}
		s := stateForTest(t, candidate)
		v := readSuccess(t, s, q)
		if status == "replaced" {
			if len(arr(v["items"])) != 0 {
				t.Fatal("replaced import selected as current", v)
			}
			history := copyJSON(q).(map[string]any)
			for _, r := range arr(candidate["records"]) {
				if env(r)["kind"] == "assertion" {
					obj(history["scope"])["targets"] = []any{ref(r)}
					break
				}
			}
			if firstItem(t, readSuccess(t, s, history))["currentness"] != "historical" {
				t.Fatal("known replacement lost history")
			}
		} else if firstItem(t, v)["currentness"] != "last_received" {
			t.Fatal("unchecked import claimed current", v)
		}
	}
	// Convert only the authorized projection boundary; same checked assertion.
	p := obj(arr(snapshot["projection_rules"])[0])
	p["family"], p["audience"], p["purpose"] = "audience_projection", q["audience"], q["purpose"]
	obj(snapshot["policy"])["handles"] = []any{map[string]any{"subject": "subj:h1", "space": "space:main", "audience": q["audience"], "handle": "alias:public"}}
	s := stateForTest(t, snapshot)
	if _, r := s.Capture(0, q); r != nil {
		t.Fatal(r)
	}
	deliver := map[string]any{"op": "deliver", "actor": q["principal"], "at": q["now"], "view_operation": int64(0), "audience": q["audience"], "purpose": q["purpose"], "publication": map[string]any{"id": "publication:checked", "version": int64(1)}}
	success(t, s, deliver)
	obj(arr(s.policy()["imports"])[0])["status"] = "replaced"
	refusalUnchanged(t, s, deliver, PublicationStale)
}
