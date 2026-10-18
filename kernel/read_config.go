package kernel

// Read configuration has exact unique keys. Reject ambiguity at snapshot intake
// rather than letting record or configuration array order choose an authority.
func (s *State) validateReadConfiguration() *Refusal {
	index := recordIndex(arr(s.snapshot["records"]))
	owners := map[string]bool{}
	for _, raw := range arr(s.policy()["constraint_owners"]) {
		m := obj(raw)
		k := refKey(m["input"])
		if owners[k] || len(arr(m["owners"])) == 0 || !ordered(m["owners"]) {
			return refusal(InvalidReference)
		}
		owners[k] = true
	}
	decisions := map[string]bool{}
	for _, raw := range arr(s.policy()["declassification_decisions"]) {
		d := obj(raw)
		k := refKey(d["ref"])
		if decisions[k] || !ordered(obj(d["pins"])["inputs"]) {
			return refusal(InvalidReference)
		}
		decisions[k] = true
	}
	rules := map[string]bool{}
	for _, raw := range arr(s.snapshot["projection_rules"]) {
		p := obj(raw)
		k := refKey(p)
		if rules[k] || !ordered(p["excluded_refs"]) || p["family"] != "audience_projection" && len(arr(p["excluded_refs"])) != 0 {
			return refusal(InvalidDomainValue)
		}
		rules[k] = true
	}
	covered := map[string]bool{}
	for _, raw := range arr(s.policy()["coverage"]) {
		m := obj(raw)
		k := refKey(m["assertion"])
		declaration := index[refKey(m["declaration"])]
		if covered[k] || env(index[k])["kind"] != "assertion" || env(declaration)["kind"] != "assessment" || !equalJSON(obj(body(declaration)["pins"])["subject"], m["assertion"]) {
			return refusal(InvalidReference)
		}
		covered[k] = true
	}
	for _, name := range []string{"source_access", "imports"} {
		seen := map[string]bool{}
		for _, raw := range arr(s.policy()[name]) {
			m := obj(raw)
			k := refKey(m["source"])
			if seen[k] || env(index[k])["kind"] != "source" {
				return refusal(InvalidReference)
			}
			seen[k] = true
			if name == "imports" && m["checked_at"] != nil && !validStamp(m["checked_at"]) {
				return refusal(InvalidTime)
			}
		}
	}
	keys, values := map[string]bool{}, map[string]string{}
	for _, raw := range arr(s.policy()["handles"]) {
		m := obj(raw)
		k := key([]any{m["subject"], m["space"], m["audience"]})
		v := key([]any{m["handle"], m["space"], m["audience"]})
		if keys[k] {
			return refusal(InvalidReference)
		}
		keys[k] = true
		if subject, ok := values[v]; ok && subject != m["subject"] {
			return refusal(InvalidReference)
		}
		values[v] = m["subject"].(string)
	}
	for _, raw := range arr(s.snapshot["domain_schemas"]) {
		f := obj(obj(raw)["freshness_default"])
		if f["kind"] == "duration" && f["seconds"].(int64) < 0 {
			return refusal(InvalidTime)
		}
	}
	if !uniqueSourceOwners(s.runtime()["source_cuts"]) {
		return refusal(InvalidTime)
	}
	return nil
}
func uniqueSourceOwners(cuts any) bool {
	seen := map[string]bool{}
	for _, raw := range arr(cuts) {
		owner := obj(raw)["owner"].(string)
		if seen[owner] {
			return false
		}
		seen[owner] = true
	}
	return true
}
