package kernel

func (s *State) decision(reference any) map[string]any {
	for _, raw := range arr(s.policy()["declassification_decisions"]) {
		d := obj(raw)
		if equalJSON(d["ref"], reference) {
			return d
		}
	}
	return nil
}
func (s *State) completeLineage(r any, index map[string]any, seen map[string]bool) bool {
	if r == nil || env(r)["lineage"] == "unknown" || s.fact(r)["complete"] != true {
		return false
	}
	k := refKey(ref(r))
	if seen[k] {
		return true
	}
	seen[k] = true
	for _, v := range arr(s.fact(r)["inputs"]) {
		if !s.completeLineage(index[refKey(v)], index, seen) {
			return false
		}
	}
	return true
}
func (s *State) ownDisclosureAllows(r any, audience, purpose any) bool {
	d := obj(env(r)["disclosure"])
	if !contains(d["audiences"], audience) || !contains(d["purposes"], purpose) {
		return false
	}
	for _, field := range arr(s.domain(r)["fields"]) {
		f := obj(field)
		if contentValue(r, f["name"]) == nil {
			continue
		}
		for _, raw := range arr(s.domain(r)["disclosure_defaults"]) {
			v := obj(raw)
			if v["field_class"] == f["disclosure_class"] && (!contains(v["audiences"], audience) || !contains(v["purposes"], purpose)) {
				return false
			}
		}
	}
	return true
}
func (s *State) lineageDeadlineLive(r any, at any, index map[string]any, seen map[string]bool) bool {
	if r == nil {
		return false
	}
	k := refKey(ref(r))
	if seen[k] {
		return true
	}
	seen[k] = true
	deadline := obj(env(r)["disclosure"])["retain_until"]
	if deadline != nil && validStamp(at) && at.(string) >= deadline.(string) {
		return false
	}
	for _, v := range arr(s.fact(r)["inputs"]) {
		if !s.lineageDeadlineLive(index[refKey(v)], at, index, seen) {
			return false
		}
	}
	return true
}

// releaseValid validates evidence, not a capability. Every new disclosure calls
// it against active exact-version assessments, live owner decisions and the
// exact structured output body digest, independently of the caller's read cut.
func (s *State) releaseValid(output any, assessments []any, index map[string]any, at any) bool {
	if env(output)["kind"] != "assertion" || len(assessments) == 0 || !s.completeLineage(output, index, map[string]bool{}) {
		return false
	}
	inputs := s.fact(output)["inputs"]
	if !equalJSON(inputs, env(output)["lineage"]) {
		return false
	}
	digest, r := DigestJSON(body(output))
	if r != nil {
		return false
	}
	// Use protected revision state, including revisions hidden from this reader.
	// Replacement/correction retire the cited version; challenges do not.
	records := make([]any, 0, len(index))
	for _, record := range index {
		records = append(records, record)
	}
	active := recordIndex(s.currentRecords(records))
	refs, owners := []any{}, []any{}
	var common map[string]any
	for _, assessment := range assessments {
		b, e := body(assessment), env(assessment)
		pins, release := obj(b["pins"]), obj(b["declassification"])
		if active[refKey(ref(assessment))] == nil || !s.completeLineage(assessment, index, map[string]bool{}) || s.fenced(assessment, index, map[string]bool{}) {
			return false
		}
		if e["kind"] != "assessment" || b["check_kind"] != "declassification" || b["result"] != "pass" || b["executor"] != "human" && b["executor"] != "deterministic" || s.fact(assessment)["kind"] == "model" || e["context"] != env(output)["context"] || e["space"] != env(output)["space"] {
			return false
		}
		if !equalJSON(pins["subject"], ref(output)) || !equalJSON(pins["policy"], obj(s.policy()["evidence"])["policy_pin"]) || !equalJSON(pins["environment"], obj(s.policy()["evidence"])["environment_pin"]) || !s.lineageDeadlineLive(assessment, at, index, map[string]bool{}) {
			return false
		}
		if b["usable_until"] != nil && at.(string) >= b["usable_until"].(string) {
			return false
		}
		if !equalJSON(release["inputs"], inputs) || !equalJSON(release["output_schema"], env(output)["schema"]) || release["output_digest"] != digest {
			return false
		}
		d := s.decision(release["decision"])
		if d == nil || d["active"] != true || d["owner"] != e["issuer"] || contains(s.runtime()["revoked_declassifications"], d["ref"]) {
			return false
		}
		pinned := copyJSON(release).(map[string]any)
		delete(pinned, "decision")
		if !equalJSON(pinned, d["pins"]) || common != nil && !equalJSON(common, pinned) {
			return false
		}
		common = pinned
		refs = append(refs, ref(assessment))
		owners = append(owners, e["issuer"])
	}
	if len(set(refs)) != len(refs) || !equalJSON(set(refs), obj(env(output)["disclosure"])["declassification"]) {
		return false
	}
	audience, purpose := common["audience"], common["purpose"]
	d := obj(env(output)["disclosure"])
	if !contains(d["audiences"], audience) || !contains(d["purposes"], purpose) {
		return false
	}
	seen := map[string]bool{}
	var covered func(any) bool
	covered = func(r any) bool {
		if r == nil {
			return false
		}
		k := refKey(ref(r))
		if seen[k] {
			return true
		}
		seen[k] = true
		lifted := !s.ownDisclosureAllows(r, audience, purpose)
		for _, c := range arr(obj(env(r)["disclosure"])["field_classes"]) {
			if !contains(d["field_classes"], c) {
				lifted = true
			}
		}
		if lifted {
			required := []any{s.policy()["owner"]}
			for _, raw := range arr(s.policy()["constraint_owners"]) {
				if equalJSON(obj(raw)["input"], ref(r)) {
					required = arr(obj(raw)["owners"])
				}
			}
			for _, owner := range required {
				if !contains(owners, owner) {
					return false
				}
			}
		}
		for _, input := range arr(s.fact(r)["inputs"]) {
			if !covered(index[refKey(input)]) {
				return false
			}
		}
		return true
	}
	return covered(output)
}
func (s *State) liveRelease(r any, audience, purpose, at any, index map[string]any) bool {
	assessments := []any{}
	for _, v := range arr(obj(env(r)["disclosure"])["declassification"]) {
		a := index[refKey(v)]
		if a == nil {
			return false
		}
		assessments = append(assessments, a)
	}
	if !s.releaseValid(r, assessments, index, at) {
		return false
	}
	pins := obj(body(assessments[0])["declassification"])
	return pins["audience"] == audience && pins["purpose"] == purpose
}
func (s *State) disclosureAllows(r any, audience, purpose, at any, index map[string]any, seen map[string]bool) bool {
	if r == nil {
		return false
	}
	k := refKey(ref(r))
	if seen[k] {
		return true
	}
	seen[k] = true
	if !s.lineageDeadlineLive(r, at, index, map[string]bool{}) {
		return false
	}
	if s.liveRelease(r, audience, purpose, at, index) {
		return true
	}
	if !s.ownDisclosureAllows(r, audience, purpose) {
		return false
	}
	for _, input := range arr(s.fact(r)["inputs"]) {
		if !s.disclosureAllows(index[refKey(input)], audience, purpose, at, index, seen) {
			return false
		}
	}
	return true
}
