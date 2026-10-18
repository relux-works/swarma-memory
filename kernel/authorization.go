package kernel

func (s *State) revoked(actor, audience, purpose, right any) bool {
	for _, r := range arr(s.runtime()["revocations"]) {
		m := obj(r)
		if m["principal"] == actor && m["audience"] == audience && m["purpose"] == purpose && m["right"] == right {
			return true
		}
	}
	return false
}
func (s *State) grant(actor, space, id, audience, purpose, right any, metadata bool) bool {
	if s.revoked(actor, audience, purpose, right) {
		return false
	}
	for _, g := range arr(s.policy()["grants"]) {
		m := obj(g)
		if m["principal"] == actor && m["space"] == space && m["audience"] == audience && m["purpose"] == purpose && contains(m["rights"], right) && (contains(m["records"], id) || contains(m["records"], "*")) && (!metadata || m["metadata"] == true) {
			return true
		}
	}
	return false
}
func (s *State) operationRight(actor, space any, operation string) bool {
	right := "admit"
	if operation == "revise" {
		right = "revise"
	}
	for _, g := range arr(s.policy()["grants"]) {
		m := obj(g)
		if m["principal"] == actor && m["space"] == space && contains(m["rights"], right) && !s.revoked(actor, m["audience"], m["purpose"], right) {
			return true
		}
	}
	return false
}
func (s *State) retention(r any, ctx map[string]any, index map[string]any, seen map[string]bool) bool {
	k := refKey(ref(r))
	if seen[k] {
		return true
	}
	seen[k] = true
	e := env(r)
	c := obj(ctx["retention_context"])
	if !s.grant(ctx["actor"], e["space"], e["id"], c["audience"], c["purpose"], "retain", false) {
		return false
	}
	deadline := obj(e["disclosure"])["retain_until"]
	// Malformed timestamps are diagnosed in their later content/time class.
	if deadline != nil && validStamp(deadline) && validStamp(ctx["at"]) && ctx["at"].(string) >= deadline.(string) {
		return false
	}
	for _, v := range arr(s.fact(r)["inputs"]) {
		if input := index[refKey(v)]; input != nil && !s.retention(input, ctx, index, seen) {
			return false
		}
	}
	return true
}
func (s *State) fenced(r any, index map[string]any, seen map[string]bool) bool {
	k := refKey(ref(r))
	if seen[k] {
		return false
	}
	seen[k] = true
	if contains(s.runtime()["fences"], ref(r)) || contains(s.runtime()["erased"], ref(r)) {
		return true
	}
	for _, v := range arr(s.fact(r)["inputs"]) {
		if contains(s.runtime()["fences"], v) || contains(s.runtime()["erased"], v) {
			return true
		}
		if input := index[refKey(v)]; input != nil && s.fenced(input, index, seen) {
			return true
		}
	}
	return false
}
func (s *State) representation(e map[string]any, actor any, relation string) bool {
	if e["issuer"] == actor {
		return e["representation_ref"] == nil
	}
	if e["representation_ref"] == nil {
		return false
	}
	for _, r := range arr(s.policy()["representations"]) {
		m := obj(r)
		if refKey(m["ref"]) == refKey(e["representation_ref"]) && m["issuer"] == e["issuer"] && m["submitter"] == actor && m["space"] == e["space"] && m["valid"] == true && contains(m["relations"], relation) {
			return true
		}
	}
	return false
}
func (s *State) reviewed(r any) bool {
	allowed := false
	for _, review := range arr(s.policy()["reviews"]) {
		m := obj(review)
		if !equalJSON(m["record"], ref(r)) {
			continue
		}
		if m["result"] != "allow" {
			return false
		}
		allowed = true
	}
	return allowed
}

func (s *State) taint(batch []any, index map[string]any) {
	// Intersections and unions are monotone on a finite set, including cycles in
	// content lineage (logical sufficient-support cycles are separately forbidden).
	for changed := true; changed; {
		changed = false
		for _, r := range batch {
			d := obj(env(r)["disclosure"])
			before := key(d)
			merge := func(other map[string]any) {
				for _, field := range []string{"audiences", "purposes"} {
					out := []any{}
					for _, v := range arr(d[field]) {
						if contains(other[field], v) {
							out = append(out, v)
						}
					}
					d[field] = set(out)
				}
				d["field_classes"] = set(append(arr(d["field_classes"]), arr(other["field_classes"])...))
				if t := other["retain_until"]; t != nil && (d["retain_until"] == nil || t.(string) < d["retain_until"].(string)) {
					d["retain_until"] = t
				}
			}
			if env(r)["kind"] == "assertion" {
				domain := s.domain(r)
				for _, f := range arr(domain["fields"]) {
					if contentValue(r, obj(f)["name"]) == nil {
						continue
					}
					class := obj(f)["disclosure_class"]
					d["field_classes"] = set(append(arr(d["field_classes"]), class))
					for _, defaults := range arr(domain["disclosure_defaults"]) {
						v := obj(defaults)
						if v["field_class"] == class {
							merge(map[string]any{"audiences": v["audiences"], "purposes": v["purposes"], "field_classes": []any{}, "retain_until": nil})
						}
					}
				}
			}
			for _, v := range arr(s.fact(r)["inputs"]) {
				if input := index[refKey(v)]; input != nil {
					merge(obj(env(input)["disclosure"]))
				}
			}
			if key(d) != before {
				changed = true
			}
		}
	}
}
