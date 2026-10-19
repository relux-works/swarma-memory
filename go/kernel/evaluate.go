package kernel

import "sort"

type signedRef struct {
	assertion any
	polarity  string
}
type evidencePath struct {
	refs, origins, qualifications []any
	premises                      []signedRef
	source                        int // weakest AND premise; strongest OR alternative (0 prior, 1 independent, 2 resolved)
}
type evaluation struct {
	paths    []evidencePath
	complete bool
	cutoffs  []any
	quality  string
}

func emptyEvaluation() evaluation {
	return evaluation{paths: []evidencePath{}, complete: true, cutoffs: []any{}, quality: "not_fully_checked"}
}
func (r evaluation) proofs() []any {
	out := []any{}
	for _, p := range r.paths {
		x := set(p.refs)
		out = append(out, x)
	}
	return set(out)
}

type evidenceWalk struct {
	g        *readGraph
	used     map[string]int64
	sources  map[string]bool
	memo     map[string]evaluation
	visiting map[string]bool
}

func (g *readGraph) evaluate(assertion any, polarity string, quality bool) evaluation {
	w := &evidenceWalk{g: g, used: map[string]int64{}, sources: map[string]bool{}, memo: map[string]evaluation{}, visiting: map[string]bool{}}
	result := w.literal(assertion, polarity)
	if !quality || len(result.paths) == 0 {
		return result
	}
	opposite := map[string]evaluation{}
	allTainted := true
	for _, path := range result.paths {
		tainted, unchecked := false, false
		for _, p := range path.premises {
			pol := "support"
			if p.polarity == "support" {
				pol = "oppose"
			}
			k := refKey(p.assertion) + ":" + pol
			r, ok := opposite[k]
			if !ok {
				r = g.evaluate(p.assertion, pol, false)
				opposite[k] = r
			}
			if len(r.paths) > 0 {
				tainted = true
			} else if !r.complete {
				unchecked = true
			}
		}
		if !tainted && !unchecked {
			result.quality = "clean_path"
			return result
		}
		if !tainted {
			allTainted = false
		}
	}
	if result.complete && allTainted {
		result.quality = "conflicted_premises_only"
	}
	return result
}
func (w *evidenceWalk) visit(name, cutoff string, r *evaluation) bool {
	if w.used[name] >= w.g.bounds[name] {
		r.complete = false
		r.cutoffs = append(r.cutoffs, cutoff)
		return false
	}
	w.used[name]++
	return true
}
func (w *evidenceWalk) literal(assertion any, polarity string) evaluation {
	k := refKey(assertion) + ":" + polarity
	if r, ok := w.memo[k]; ok {
		return r
	}
	r := emptyEvaluation()
	g := w.g
	target := g.index[refKey(assertion)]
	if !g.allowed(target) || g.withdrawn(target) || w.visiting[k] {
		return r
	}
	w.visiting[k] = true
	defer delete(w.visiting, k)
	literal := map[string]any{"assertion": assertion, "polarity": polarity}
	for _, root := range g.records {
		b := body(root)
		if !g.assessmentEligible(root) || !equalJSON(b["target"], literal) || !equalJSON(obj(b["pins"])["subject"], assertion) || !contains(obj(g.s.policy()["evidence"])["root_kinds"], b["check_kind"]) {
			continue
		}
		if !w.visit("roots", "root_limit", &r) {
			continue
		}
		resolved := true
		missing := false
		for _, src := range arr(b["sources"]) {
			if b["source_requirement"] == "current" && !w.sources[refKey(src)] {
				if !w.visit("source_resolutions", "source_limit", &r) {
					missing = true
					continue
				}
				w.sources[refKey(src)] = true
			}
			if !g.sourceAvailable(g.index[refKey(src)]) {
				resolved = false
			}
		}
		if missing {
			continue
		}
		if !resolved && b["source_requirement"] == "current" {
			r.complete = false
			r.cutoffs = append(r.cutoffs, "source_unavailable")
			continue
		}
		state := 2
		if !resolved {
			state = 0
			if b["source_requirement"] == "independent" {
				state = 1
			}
		}
		r.paths = append(r.paths, evidencePath{refs: []any{ref(root)}, origins: []any{b["origin"]}, qualifications: []any{b["check_kind"]}, source: state})
	}
	for _, rule := range g.records {
		b := body(rule)
		if b["role"] != "sufficient_support" || !equalJSON(b["target"], literal) || !g.ruleEligible(rule, false) {
			continue
		}
		if !w.visit("rules", "rule_limit", &r) {
			continue
		}
		premises := append([]any{}, arr(b["premises"])...)
		sort.Slice(premises, func(i, j int) bool {
			a, c := obj(obj(premises[i])["literal"]), obj(obj(premises[j])["literal"])
			if !equalJSON(a["assertion"], c["assertion"]) {
				return lessRef(a["assertion"], c["assertion"])
			}
			return a["polarity"].(string) < c["polarity"].(string)
		})
		combinations := []evidencePath{{refs: []any{ref(rule)}, origins: []any{}, qualifications: []any{"formal_entailment"}, source: 2}}
		for _, p := range premises {
			lit := obj(obj(p)["literal"])
			sub := w.literal(lit["assertion"], lit["polarity"].(string))
			if !sub.complete {
				r.complete = false
			}
			r.cutoffs = append(r.cutoffs, sub.cutoffs...)
			next := []evidencePath{}
			for _, left := range combinations {
				for _, right := range sub.paths {
					joined := evidencePath{refs: set(append(append([]any{}, left.refs...), right.refs...)), origins: set(append(append([]any{}, left.origins...), right.origins...)), qualifications: set(append(append([]any{}, left.qualifications...), right.qualifications...)), source: min(left.source, right.source)}
					joined.premises = append(append(append([]signedRef{}, left.premises...), right.premises...), signedRef{lit["assertion"], lit["polarity"].(string)})
					next = append(next, joined)
				}
			}
			combinations = uniquePaths(next)
		}
		r.paths = append(r.paths, combinations...)
	}
	r.cutoffs = set(r.cutoffs)
	r.paths = uniquePaths(r.paths)
	w.memo[k] = r
	return r
}
func (g *readGraph) associatedSources(r any) []any { return g.collectSources(r, true) }
func (g *readGraph) collectSources(r any, recursive bool) []any {
	out := []any{}
	seen := map[string]bool{}
	var collect func(any)
	collect = func(r any) {
		if r == nil || seen[refKey(ref(r))] {
			return
		}
		seen[refKey(ref(r))] = true
		if receipt := body(r)["authority_receipt"]; receipt != nil && g.allowed(g.index[refKey(receipt)]) {
			out = append(out, receipt)
		}
		for _, candidate := range g.records {
			b := body(candidate)
			if env(candidate)["kind"] == "assessment" && g.live(candidate) && equalJSON(obj(b["target"])["assertion"], ref(r)) {
				// An inaccessible named source filters the entire assessment association.
				permitted := true
				for _, source := range arr(b["sources"]) {
					if !g.allowed(g.index[refKey(source)]) {
						permitted = false
					}
				}
				if permitted {
					out = append(out, arr(b["sources"])...)
				}
			}
			if env(candidate)["kind"] == "justification" && g.ruleEligible(candidate, false) && equalJSON(obj(b["target"])["assertion"], ref(r)) {
				for _, p := range arr(b["premises"]) {
					if obj(p)["kind"] == "source" {
						out = append(out, obj(p)["source"])
					} else if recursive && b["role"] == "sufficient_support" {
						collect(g.index[refKey(obj(obj(p)["literal"])["assertion"])])
					}
				}
			}
		}
	}
	collect(r)
	out = set(out)
	return out
}
func (g *readGraph) channel(assertion any, result evaluation, handle, freshness string) map[string]any {
	witness := "not_found"
	if len(result.paths) > 0 {
		witness = "present"
	}
	status := "complete"
	if !result.complete {
		status = "incomplete"
	}
	qualifications, origins := []any{}, []any{}
	source := 0
	for _, p := range result.paths {
		qualifications = append(qualifications, p.qualifications...)
		origins = append(origins, p.origins...)
		source = max(source, p.source)
	}
	if len(result.paths) == 0 {
		source = 2
		for _, src := range g.collectSources(assertion, false) {
			if !g.sourceAvailable(g.index[refKey(src)]) {
				source = 0
			}
		}
	}
	coverage := map[string]any{"kind": "unknown"}
	for _, raw := range arr(g.s.policy()["coverage"]) {
		m := obj(raw)
		if equalJSON(m["assertion"], ref(assertion)) && g.assessmentEligible(g.index[refKey(m["declaration"])]) {
			coverage = map[string]any{"kind": "declared", "ref": copyJSON(m["declaration"])}
		}
	}
	origins = set(origins)
	return map[string]any{"witness": witness, "evaluation": status, "corpus_coverage": coverage, "premise_quality": result.quality, "evidence_qualification": set(qualifications), "source_state": []string{"prior_assessment_only", "independent_attestation", "resolvable_now"}[source], "freshness": freshness, "authorized_snapshot_handle": handle, "dependency_coverage": "registered_only", "witness_roots": origins, "independent_root_count": int64(len(origins))}
}

// Deduplicate after each AND join, not only when rendering. Repeated premises
// and shared subgraphs otherwise enumerate identical proof sets exponentially.
func uniquePaths(paths []evidencePath) []evidencePath {
	out := make([]evidencePath, 0, len(paths))
	seen := map[string]bool{}
	for _, p := range paths {
		literals := map[string]signedRef{}
		for _, v := range p.premises {
			literals[refKey(v.assertion)+":"+v.polarity] = v
		}
		names := make([]string, 0, len(literals))
		for k := range literals {
			names = append(names, k)
		}
		sort.Strings(names)
		p.premises = nil
		encoded := []any{}
		for _, k := range names {
			v := literals[k]
			p.premises = append(p.premises, v)
			encoded = append(encoded, map[string]any{"assertion": v.assertion, "polarity": v.polarity})
		}
		p.refs = set(p.refs)
		p.origins = set(p.origins)
		p.qualifications = set(p.qualifications)
		k := key([]any{p.refs, p.origins, p.qualifications, int64(p.source), encoded})
		if !seen[k] {
			seen[k] = true
			out = append(out, p)
		}
	}
	return out
}
