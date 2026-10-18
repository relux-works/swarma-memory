package kernel

// deliver validates the saved exact selection against current authority. It
// returns a data-only receipt; no publisher or external process is invoked.
func (s *State) deliver(op map[string]any) (map[string]any, *Refusal) {
	c, ok := s.captures[op["view_operation"].(int64)]
	if !ok {
		return nil, refusal(InvalidReference)
	}
	q := copyJSON(c.query).(map[string]any)
	if op["actor"] != q["principal"] || op["audience"] != q["audience"] || op["purpose"] != q["purpose"] {
		return nil, refusal(NotAuthorized)
	}
	var projection map[string]any
	for _, raw := range arr(s.snapshot["projection_rules"]) {
		if equalJSON(q["projection_rule"], map[string]any{"id": obj(raw)["id"], "version": obj(raw)["version"]}) {
			projection = obj(raw)
		}
	}
	if projection == nil || projection["family"] != "audience_projection" {
		return nil, refusal(NotAuthorized)
	}
	if !equalJSON(q["policy"], s.policy()["revision"]) || !equalJSON(q["evidence_policy"], obj(s.policy()["evidence"])["ref"]) {
		return nil, refusal(DisclosureRevoked)
	}
	if !validStamp(op["at"]) {
		return nil, refusal(InvalidTime)
	}
	if badVersion(op["publication"]) {
		return nil, refusal(InvalidDomainValue)
	}
	if obj(s.runtime()["restore"])["status"] != "open" {
		return nil, refusal(ErasureFenced)
	}
	q["now"] = op["at"]
	q["cut"] = map[string]any{"memory": s.runtime()["memory_cut"], "sources": copyJSON(s.runtime()["source_cuts"])}
	g := s.newReadGraph(q, projection, map[string]int64{})
	for _, v := range c.refs {
		r := g.index[refKey(v)]
		if r == nil || g.fenced[refKey(v)] {
			return nil, refusal(ErasureFenced)
		}
		for _, right := range []string{"read", "use", "forward"} {
			if !s.grant(op["actor"], env(r)["space"], env(r)["id"], op["audience"], op["purpose"], right, true) {
				return nil, refusal(DisclosureRevoked)
			}
		}
		if !g.allowed(r) || !g.boundedLineage(r, map[string]bool{}) || contains(projection["excluded_refs"], v) {
			return nil, refusal(DisclosureRevoked)
		}
		if _, freshness := g.freshness(r); freshness == "stale" {
			return nil, refusal(PublicationStale)
		}
		if !g.current(r) || g.withdrawn(r) || g.importCurrentness(r) == "last_received" {
			return nil, refusal(PublicationStale)
		}
	}
	h, refusal := s.nextHandle()
	if refusal != nil {
		return nil, refusal
	}
	return receipt("deliver", "delivered", h, []any{}, []any{}, nil), nil
}
