package kernel

import "sort"

// capturedView retains a detached immutable result and its protected query binding.
type capturedView struct{ query, view map[string]any }

type readGraph struct {
	s             *State
	q, projection map[string]any
	records       []any
	index         map[string]any
	eligible      map[string]bool
	fenced        map[string]bool
	active        map[string]bool
	bounds        map[string]int64
}

// Read validates a complete closed query, filters authority before logical work,
// and evaluates a detached view. No read changes the admitted snapshot.
func (s *State) Read(q map[string]any) (map[string]any, *Refusal) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.read(q)
}

// Capture binds a successful immutable view to the harness operation index.
// Indexes are protected bindings, never public global cursors.
func (s *State) Capture(index int64, q map[string]any) (map[string]any, *Refusal) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if index < 0 {
		return nil, refusal(InvalidShape)
	}
	if _, exists := s.captures[index]; exists {
		return nil, refusal(InvalidReference)
	}
	v, r := s.read(q)
	if r != nil {
		return nil, r
	}
	if s.captures == nil {
		s.captures = map[int64]capturedView{}
	}
	s.captures[index] = capturedView{copyJSON(q).(map[string]any), copyJSON(v).(map[string]any)}
	return v, nil
}

// Captured returns a detached historical result; it grants no current authority.
func (s *State) Captured(index int64) map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.captures[index]
	if !ok {
		return nil
	}
	return copyJSON(c.view).(map[string]any)
}

func (s *State) read(q map[string]any) (map[string]any, *Refusal) {
	if _, r := CanonicalJSON(q); r != nil {
		return nil, r
	}
	q = copyJSON(q).(map[string]any)
	if !s.schemas.roots[packageSchema+"query"].matches(q, nil) {
		return nil, refusal(InvalidShape)
	}
	for _, name := range []string{"roots", "rules", "source_resolutions", "explanations"} {
		if obj(q["bounds"])[name].(int64) < 0 {
			return nil, refusal(InvalidShape)
		}
	}
	scope := obj(q["scope"])
	var domain, projection map[string]any
	for _, raw := range arr(s.snapshot["domain_schemas"]) {
		m := obj(raw)
		if equalJSON(scope["schema"], map[string]any{"id": m["id"], "version": m["version"]}) {
			domain = m
		}
	}
	if domain == nil {
		return nil, refusal(UnknownSchema)
	}
	for _, raw := range arr(s.snapshot["projection_rules"]) {
		m := obj(raw)
		if equalJSON(q["projection_rule"], map[string]any{"id": m["id"], "version": m["version"]}) {
			projection = m
		}
	}
	if projection == nil {
		return nil, refusal(UnknownRule)
	}
	if !equalJSON(q["policy"], s.policy()["revision"]) || !equalJSON(q["evidence_policy"], obj(s.policy()["evidence"])["ref"]) {
		return nil, refusal(PolicyMismatch)
	}
	if s.policy()["public_availability"] == "degraded" && s.policy()["availability_disclosure"] == "coarse_unavailable" {
		return nil, refusal(Unavailable)
	}
	if obj(s.runtime()["restore"])["status"] != "open" {
		return nil, refusal(ErasureFenced)
	}
	if q["valid_at"] != "any" && !validStamp(q["valid_at"]) || !validStamp(q["now"]) || q["usable_until"] != nil && !validStamp(q["usable_until"]) {
		return nil, refusal(InvalidTime)
	}
	cut := obj(q["cut"])
	if !uniqueSourceOwners(cut["sources"]) || !contains(s.runtime()["committed_cuts"], cut["memory"]) || cut["memory"].(int64) > s.runtime()["memory_cut"].(int64) || !equalJSON(set(arr(cut["sources"])), set(arr(s.runtime()["source_cuts"]))) {
		return nil, refusal(InvalidTime)
	}
	if projection["family"] == "audience_projection" && (projection["audience"] != q["audience"] || projection["purpose"] != q["purpose"]) {
		return nil, refusal(NotAuthorized)
	}
	bounds := map[string]int64{}
	for _, name := range []string{"roots", "rules", "source_resolutions", "explanations"} {
		n := obj(q["bounds"])[name].(int64)
		bounds[name] = min(n, obj(obj(s.policy()["limits"])["read"])[name].(int64))
	}
	var prior capturedView
	if q["kind"] == "changes" && q["since"] != nil {
		var ok bool
		prior, ok = s.captures[q["since"].(int64)]
		if !ok || !sameBinding(q, prior.query) {
			return nil, refusal(NotAuthorized)
		}
	}
	g := &readGraph{s: s, q: q, projection: projection, index: map[string]any{}, eligible: map[string]bool{}, fenced: map[string]bool{}, active: map[string]bool{}, bounds: bounds, records: []any{}}
	// Current disposition follows protected content lineage over the full snapshot,
	// even when the query knowledge cut excludes an intermediate input. Logical
	// evidence/source associations alone do not imply content lineage.
	fullIndex := recordIndex(arr(s.snapshot["records"]))
	for _, r := range arr(s.snapshot["records"]) {
		if obj(env(r)["recorded"])["sequence"].(int64) <= cut["memory"].(int64) {
			g.records = append(g.records, r)
			g.index[refKey(ref(r))] = r
		}
	}
	sort.Slice(g.records, func(i, j int) bool { return lessRef(ref(g.records[i]), ref(g.records[j])) })
	for _, r := range g.records {
		k := refKey(ref(r))
		g.fenced[k] = s.fenced(r, fullIndex, map[string]bool{})
		g.eligible[k] = g.visible(r)
		g.active[k] = true
	}
	// An unauthorized revision cannot change the authorized projection.
	for _, r := range g.records {
		if env(r)["kind"] == "revision" && g.eligible[refKey(ref(r))] && body(r)["relation"] != "challenge" && body(r)["relation"] != "availability" {
			g.active[refKey(body(r)["target"])] = false
		}
	}
	selected, historical, labels := g.selection()
	if projection["family"] == "audience_projection" {
		for _, r := range selected {
			for _, principal := range []any{env(r)["subject"], env(r)["issuer"], env(r)["submitter"], obj(env(r)["perspective"])["principal"]} {
				if g.alias(principal, env(r)["space"]) == nil {
					return nil, refusal(NotAuthorized)
				}
			}
		}
	}
	handle, mintRefusal := s.nextHandle()
	if mintRefusal != nil {
		return nil, mintRefusal
	}
	view := map[string]any{"type": "view", "semantic_profile": "0.2.6-draft", "projection_rule": copyJSON(q["projection_rule"]), "evidence_policy": copyJSON(q["evidence_policy"]), "policy": copyJSON(q["policy"]), "authorized_snapshot_handle": handle, "data_classification": "data", "items": []any{}, "currentness": "none", "historical": []any{}, "review_required": []any{}, "explanation": map[string]any{"status": "complete", "paths": []any{}, "reason": nil}, "cutoffs": []any{}, "changes": map[string]any{"state": "initial", "refs": []any{}}}
	view["historical"] = historical
	review := g.reviewRequired(selected)
	view["review_required"] = review
	allpaths := []any{}
	cutoffs := []any{}
	for _, r := range selected {
		item := map[string]any{}
		for _, name := range []string{"subject", "issuer", "submitter", "perspective", "representation_ref", "admission_class", "valid", "confirmed_at"} {
			item[name] = copyJSON(env(r)[name])
		}
		for _, name := range []string{"statement_kind", "content", "authority_receipt"} {
			item[name] = copyJSON(body(r)[name])
		}
		item["ref"] = ref(r)
		item["currentness"] = labels[refKey(ref(r))]
		item["source_refs"] = g.associatedSources(r)
		item["incompatible_with"] = g.incompatible(r)
		horizon, freshness := g.freshness(r)
		item["usable_until"] = horizon
		dirty := g.dirty(r)
		item["needs_review"] = contains(review, ref(r))
		for _, polarity := range []string{"support", "oppose"} {
			result := g.evaluate(ref(r), polarity, true)
			if dirty {
				result = emptyEvaluation()
				result.complete = false
				result.cutoffs = []any{"dirty"}
			}
			channel := g.channel(r, result, handle, freshness)
			item[polarity] = channel
			allpaths = append(allpaths, result.proofs()...)
			cutoffs = append(cutoffs, result.cutoffs...)
		}
		if projection["family"] == "audience_projection" {
			if !g.redact(item, r) {
				return nil, refusal(NotAuthorized)
			}
		}
		view["items"] = append(arr(view["items"]), item)
		if item["currentness"] == "ambiguous_current" {
			view["currentness"] = "ambiguous_current"
		} else if view["currentness"] != "ambiguous_current" {
			if item["currentness"] == "last_received" {
				view["currentness"] = "last_received"
			} else if view["currentness"] != "last_received" {
				view["currentness"] = "current"
			}
		}
	}
	view["cutoffs"] = set(cutoffs)
	if q["kind"] == "explain" {
		paths := set(allpaths)
		ex := obj(view["explanation"])
		incomplete := false
		for _, r := range arr(view["items"]) {
			for _, p := range []string{"support", "oppose"} {
				if obj(obj(r)[p])["evaluation"] == "incomplete" {
					incomplete = true
				}
			}
		}
		if int64(len(paths)) > bounds["explanations"] {
			paths = paths[:bounds["explanations"]]
			ex["status"] = "partial"
			ex["reason"] = "explanation_limit"
		} else if incomplete {
			ex["status"] = "partial"
			ex["reason"] = "evaluation_limit"
		}
		// Audience projections do not disclose proof vertices.
		if projection["family"] == "audience_projection" {
			paths = []any{}
		}
		ex["paths"] = paths
	}
	if projection["family"] == "audience_projection" {
		view["historical"] = []any{}
		view["review_required"] = []any{}
	}
	if q["kind"] == "changes" && q["since"] != nil {
		state := "no_change"
		refs := []any{}
		if !equalJSON(changeProjection(view), changeProjection(prior.view)) {
			state = "changed"
			old := map[string]any{}
			for _, v := range arr(prior.view["items"]) {
				old[refKey(obj(v)["ref"])] = comparableItem(obj(v))
			}
			for _, v := range arr(view["items"]) {
				m := obj(v)
				if m["ref"] != nil && !equalJSON(comparableItem(m), old[refKey(m["ref"])]) {
					refs = append(refs, m["ref"])
				}
			}
		}
		view["changes"] = map[string]any{"state": state, "refs": refs}
	}
	return copyJSON(view).(map[string]any), nil
}
func lessRef(a, b any) bool {
	x, y := obj(a), obj(b)
	if x["id"] != y["id"] {
		return x["id"].(string) < y["id"].(string)
	}
	return x["version"].(int64) < y["version"].(int64)
}
func sameBinding(a, b map[string]any) bool {
	for _, k := range []string{"principal", "purpose", "audience", "projection_rule"} {
		if !equalJSON(a[k], b[k]) {
			return false
		}
	}
	for _, k := range []string{"space", "subject", "schema"} {
		if !equalJSON(obj(a["scope"])[k], obj(b["scope"])[k]) {
			return false
		}
	}
	return true
}
func comparableItem(v map[string]any) map[string]any {
	m := copyJSON(v).(map[string]any)
	for _, p := range []string{"support", "oppose"} {
		delete(obj(m[p]), "authorized_snapshot_handle")
	}
	return m
}
func comparableView(v map[string]any) map[string]any {
	m := copyJSON(v).(map[string]any)
	delete(m, "authorized_snapshot_handle")
	delete(m, "changes")
	for i, r := range arr(m["items"]) {
		arr(m["items"])[i] = comparableItem(obj(r))
	}
	return m
}

func changeProjection(v map[string]any) map[string]any {
	m := comparableView(v)
	delete(m, "explanation")
	return m
}

func (g *readGraph) visible(r any) bool {
	if r == nil {
		return false
	}
	e := env(r)
	// A separately authorized source header may survive disposition, but no
	// affected payload or assessment may contribute to selection or evaluation.
	if e["kind"] != "source" && g.fenced[refKey(ref(r))] {
		return false
	}
	scope := obj(g.q["scope"])
	if e["space"] != scope["space"] || e["subject"] != scope["subject"] || e["context"] != g.q["mode"] || e["kind"] != "source" && !equalJSON(e["perspective"], g.projection["perspective"]) {
		return false
	}
	if g.q["valid_at"] != "any" {
		v := obj(e["valid"])
		if v["kind"] != "known" || g.q["valid_at"].(string) < v["from"].(string) || v["to"] != nil && g.q["valid_at"].(string) >= v["to"].(string) {
			return false
		}
	}
	if g.projection["family"] == "audience_projection" && !g.boundedLineage(r, map[string]bool{}) {
		return false
	}
	d := obj(e["disclosure"])
	if d["retain_until"] != nil && g.q["now"].(string) >= d["retain_until"].(string) {
		return false
	}
	if !contains(d["audiences"], g.q["audience"]) || !contains(d["purposes"], g.q["purpose"]) {
		return false
	}
	for _, right := range []string{"read", "use"} {
		if !g.s.grant(g.q["principal"], e["space"], e["id"], g.q["audience"], g.q["purpose"], right, true) {
			return false
		}
	}
	return true
}
func (g *readGraph) allowed(r any) bool { return r != nil && g.eligible[refKey(ref(r))] }
func (g *readGraph) live(r any) bool    { return g.allowed(r) && g.active[refKey(ref(r))] }
func (g *readGraph) withdrawn(r any) bool {
	for _, v := range g.records {
		if env(v)["kind"] == "revision" && g.allowed(v) && body(v)["relation"] == "withdraw" && equalJSON(body(v)["target"], ref(r)) {
			return true
		}
	}
	return false
}
func (g *readGraph) sourceAvailable(source any) bool {
	if source == nil || g.fenced[refKey(ref(source))] {
		return false
	}
	available := body(source)["availability"] == "resolvable"
	// Revision effects are ordered by their admitted sequence, not input order.
	seq := int64(-1)
	for _, r := range g.records {
		if env(r)["kind"] == "revision" && g.allowed(r) && body(r)["relation"] == "availability" && equalJSON(body(r)["target"], ref(source)) {
			n := obj(env(r)["recorded"])["sequence"].(int64)
			if n > seq {
				seq = n
				available = body(r)["availability"] == "resolvable"
			}
		}
	}
	for _, raw := range arr(g.s.policy()["source_access"]) {
		m := obj(raw)
		if equalJSON(m["source"], ref(source)) && m["resolvable"] == false {
			available = false
		}
	}
	return available
}
func (g *readGraph) assessmentEligible(r any) bool {
	if !g.live(r) || env(r)["kind"] != "assessment" {
		return false
	}
	b := body(r)
	p := obj(b["pins"])
	e := obj(g.s.policy()["evidence"])
	if b["result"] != "pass" || !equalJSON(p["policy"], e["policy_pin"]) || !equalJSON(p["environment"], e["environment_pin"]) || b["usable_until"] != nil && g.q["now"].(string) >= b["usable_until"].(string) {
		return false
	}
	if g.projection["family"] == "observer_model" && env(r)["issuer"] != g.projection["issuer"] {
		return false
	}
	for _, src := range arr(b["sources"]) {
		if !g.allowed(g.index[refKey(src)]) {
			return false
		}
	}
	return true
}
func (g *readGraph) ruleEligible(r any, impact bool) bool {
	if !g.allowed(r) || !impact && !g.live(r) || env(r)["kind"] != "justification" {
		return false
	}
	b := body(r)
	if b["role"] == "sufficient_support" {
		c := g.index[refKey(b["check"])]
		if !g.assessmentEligible(c) {
			return false
		}
		p := obj(body(c)["pins"])
		if !equalJSON(p["subject"], ref(r)) || !equalJSON(p["rule"], b["rule"]) {
			return false
		}
	}
	if !g.allowed(g.index[refKey(obj(b["target"])["assertion"])]) {
		return false
	}
	for _, v := range arr(b["premises"]) {
		p := obj(v)
		x := p["source"]
		if p["kind"] == "assertion" {
			x = obj(p["literal"])["assertion"]
		}
		if !g.allowed(g.index[refKey(x)]) {
			return false
		}
	}
	return true
}

// Recall implements the typed interface over the same complete query path.
func (s *State) Recall(ctx Context, q Query) (View, *Refusal) {
	v, r := s.typedRead(ctx, map[string]any(q), "recall", nil, nil, nil)
	return View(v), r
}

// Explain uses Context.ReadQuery for the pins and an exact target plus bounds.
func (s *State) Explain(ctx Context, a VersionRef, b Bounds) (Explanation, *Refusal) {
	v, r := s.typedRead(ctx, map[string]any(ctx.ReadQuery), "explain", map[string]any(a), nil, map[string]any(b))
	return Explanation(v), r
}

// Changes compares with a protected capture binding under Context.ReadQuery.
func (s *State) Changes(ctx Context, c Cursor, b Bounds) (ChangeSet, *Refusal) {
	v, r := s.typedRead(ctx, map[string]any(ctx.ReadQuery), "changes", nil, map[string]any(c), map[string]any(b))
	return ChangeSet(v), r
}
func (s *State) typedRead(ctx Context, q map[string]any, kind string, target, cursor, bounds map[string]any) (map[string]any, *Refusal) {
	if q == nil {
		return nil, refusal(InvalidShape)
	}
	q = copyJSON(q).(map[string]any)
	q["kind"] = kind
	if ctx.Actor != "" {
		q["principal"] = ctx.Actor
	}
	if target != nil {
		scope := obj(q["scope"])
		if scope == nil {
			return nil, refusal(InvalidShape)
		}
		scope["targets"] = []any{target}
	}
	if cursor != nil {
		q["since"] = cursor["since"]
	}
	if bounds != nil {
		q["bounds"] = bounds
	}
	return s.Read(q)
}

// Complete direct tracking cannot bound an unknown transitive derivation.
func (g *readGraph) boundedLineage(r any, seen map[string]bool) bool {
	if r == nil || env(r)["lineage"] == "unknown" {
		return false
	}
	k := refKey(ref(r))
	if seen[k] {
		return true
	}
	seen[k] = true
	for _, input := range arr(g.s.fact(r)["inputs"]) {
		if !g.boundedLineage(g.index[refKey(input)], seen) {
			return false
		}
	}
	return true
}
