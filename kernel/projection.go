package kernel

import (
	"fmt"
	"strconv"
)

func (g *readGraph) current(r any) bool {
	if body(r)["statement_kind"] != "decision_record" {
		return g.active[refKey(ref(r))]
	}
	receipt := body(r)["authority_receipt"]
	event := g.s.event(receipt)
	if event == nil || event["canonical"] != true || event["issuer"] != env(r)["issuer"] || !g.allowed(g.index[refKey(receipt)]) {
		return false
	}
	for _, other := range g.records {
		if env(other)["kind"] == "assertion" && g.allowed(other) && g.s.sequence(other) == g.s.sequence(r) {
			er := body(other)["authority_receipt"]
			ev := g.s.event(er)
			if ev != nil && ev["canonical"] == true && ev["issuer"] == env(r)["issuer"] && g.allowed(g.index[refKey(er)]) && g.s.precedes(env(r)["issuer"], receipt, er) {
				return false
			}
		}
	}
	return true
}
func (g *readGraph) selection() ([]any, []any, map[string]string) {
	candidates := []any{}
	selected := []any{}
	historical := []any{}
	labels := map[string]string{}
	scope := obj(g.q["scope"])
	targets := arr(scope["targets"])
	for _, r := range g.records {
		if env(r)["kind"] != "assertion" || !g.allowed(r) || env(r)["issuer"] != g.projection["issuer"] || !equalJSON(env(r)["schema"], scope["schema"]) || contains(g.projection["excluded_refs"], ref(r)) || g.withdrawn(r) {
			continue
		}
		if body(r)["statement_kind"] == "decision_record" {
			e := g.s.event(body(r)["authority_receipt"])
			if e == nil || e["canonical"] != true || e["issuer"] != env(r)["issuer"] || !g.allowed(g.index[refKey(body(r)["authority_receipt"])]) {
				continue
			}
		}
		candidates = append(candidates, r)
	}
	sequences := map[string]bool{}
	for _, r := range candidates {
		current := g.current(r)
		explicit := contains(targets, ref(r))
		if len(targets) == 0 && current || explicit {
			selected = append(selected, r)
			sequences[g.s.sequence(r)] = true
			label := "current"
			if !current {
				label = "historical"
			}
			if current && body(r)["statement_kind"] == "decision_record" {
				n := 0
				for _, other := range candidates {
					if g.s.sequence(r) == g.s.sequence(other) && g.current(other) {
						n++
					}
				}
				if n > 1 {
					label = "ambiguous_current"
				}
			}
			if current && g.importCurrentness(r) == "last_received" {
				label = "last_received"
			}
			labels[refKey(ref(r))] = label
		}
	}
	// Explicit targets also identify their sequence even when a target is not valid
	// at the selected instant. They never make an unauthorized sequence visible.
	for _, r := range candidates {
		if contains(targets, ref(r)) {
			sequences[g.s.sequence(r)] = true
		}
	}
	for _, r := range candidates {
		if sequences[g.s.sequence(r)] && !g.current(r) && !contains(targets, ref(r)) {
			historical = append(historical, ref(r))
		}
	}
	return selected, set(historical), labels
}
func (g *readGraph) importCurrentness(r any) string {
	for _, src := range g.associatedSources(r) {
		if body(g.index[refKey(src)])["source_kind"] != "publication" {
			continue
		}
		found := false
		for _, raw := range arr(g.s.policy()["imports"]) {
			m := obj(raw)
			if equalJSON(m["source"], src) && m["status"] == "current" && m["checked_at"] != nil {
				found = true
			}
		}
		if !found {
			return "last_received"
		}
	}
	return "current"
}
func (g *readGraph) incompatible(r any) []any {
	out := []any{}
	if !g.current(r) {
		return out
	}
	for _, other := range g.records {
		if env(other)["kind"] != "assertion" || equalJSON(ref(other), ref(r)) || !g.allowed(other) || !g.current(other) || !equalJSON(env(r)["schema"], env(other)["schema"]) || !equalJSON(env(r)["perspective"], env(other)["perspective"]) || env(r)["subject"] != env(other)["subject"] || env(r)["space"] != env(other)["space"] || body(r)["slot"] != body(other)["slot"] {
			continue
		}
		a, b := obj(env(r)["valid"]), obj(env(other)["valid"])
		if a["kind"] != "known" || b["kind"] != "known" || a["to"] != nil && a["to"].(string) <= b["from"].(string) || b["to"] != nil && b["to"].(string) <= a["from"].(string) {
			continue
		}
		for _, raw := range arr(g.s.domain(r)["incompatibilities"]) {
			m := obj(raw)
			if contains(m["statement_kinds"], body(r)["statement_kind"]) && contains(m["statement_kinds"], body(other)["statement_kind"]) && !equalJSON(contentField(r, m["field"]), contentField(other, m["field"])) {
				out = append(out, ref(other))
			}
		}
	}
	out = set(out)
	return out
}
func contentField(r, field any) any {
	for _, p := range arr(body(r)["content"]) {
		if obj(p)["field"] == field {
			return obj(p)["value"]
		}
	}
	return nil
}

func (g *readGraph) before(sequence int64) *readGraph {
	h := *g
	h.records = []any{}
	h.active = map[string]bool{}
	for _, r := range g.records {
		if obj(env(r)["recorded"])["sequence"].(int64) < sequence {
			h.records = append(h.records, r)
			h.active[refKey(ref(r))] = true
		}
	}
	for _, r := range h.records {
		if env(r)["kind"] == "revision" && h.allowed(r) && body(r)["relation"] != "challenge" && body(r)["relation"] != "availability" {
			h.active[refKey(body(r)["target"])] = false
		}
	}
	return &h
}

// impact computes only authorized registered dependency paths at the instant
// immediately before a cause. A later withdrawal cannot erase that cause.
func (g *readGraph) impact(revision any) map[string]bool {
	changed := map[string]bool{}
	if !g.allowed(revision) || !g.allowed(g.index[refKey(body(revision)["target"])]) {
		return changed
	}
	h := g.before(obj(env(revision)["recorded"])["sequence"].(int64))
	changed[refKey(body(revision)["target"])] = true
	for again := true; again; {
		again = false
		for _, r := range h.records {
			b := body(r)
			if b["role"] != "sufficient_support" && b["role"] != "review_on_change" || !h.ruleEligible(r, false) {
				continue
			}
			hit := changed[refKey(ref(r))] || b["check"] != nil && changed[refKey(b["check"])]
			for _, p := range arr(b["premises"]) {
				m := obj(p)
				v := m["source"]
				if m["kind"] == "assertion" {
					v = obj(m["literal"])["assertion"]
				}
				hit = hit || changed[refKey(v)]
			}
			target := refKey(obj(b["target"])["assertion"])
			if hit && !changed[target] {
				changed[target] = true
				again = true
			}
		}
	}
	return changed
}
func (g *readGraph) dirty(r any) bool {
	if !contains(g.s.runtime()["dirty"], ref(r)) {
		return false
	}
	for _, raw := range arr(g.s.runtime()["dirty_causes"]) {
		c := obj(raw)
		if equalJSON(c["assertion"], ref(r)) {
			revision := g.index[refKey(c["revision"])]
			if revision != nil && g.impact(revision)[refKey(ref(r))] {
				return true
			}
		}
	}
	return false
}
func (g *readGraph) reviewRequired(selected []any) []any {
	selectedRefs, sequences := map[string]bool{}, map[string]bool{}
	for _, r := range selected {
		selectedRefs[refKey(ref(r))] = true
		sequences[g.s.sequence(r)] = true
	}

	out := []any{}
	for _, r := range g.records {
		if env(r)["kind"] == "assertion" && g.allowed(r) && !contains(g.projection["excluded_refs"], ref(r)) && selectedRefs[refKey(ref(r))] && g.dirty(r) {
			out = append(out, ref(r))
		}
	}
	// Review-on-change remains relevant after withdrawal, even across schemas.
	for _, revision := range g.records {
		if env(revision)["kind"] != "revision" || body(revision)["relation"] == "challenge" {
			continue
		}
		target := g.index[refKey(body(revision)["target"])]
		relevant := target != nil && sequences[g.s.sequence(target)]
		if !relevant {
			continue
		}
		impact := g.reviewImpact(revision)
		dirtyImpact := g.impact(revision)
		for _, r := range g.records {
			if g.allowed(r) && env(r)["kind"] == "assertion" && dirtyImpact[refKey(ref(r))] && g.dirty(r) {
				impact[refKey(ref(r))] = true
			}
		}
		for _, r := range g.records {
			if env(r)["kind"] == "assertion" && g.allowed(r) && impact[refKey(ref(r))] && !equalJSON(ref(r), body(revision)["target"]) && !contains(g.projection["excluded_refs"], ref(r)) {
				out = append(out, ref(r))
			}
		}
	}
	out = set(out)
	return out
}
func (g *readGraph) alias(principal, space any) any {
	for _, raw := range arr(g.s.policy()["handles"]) {
		m := obj(raw)
		if m["subject"] == principal && m["space"] == space && m["audience"] == g.q["audience"] {
			return m["handle"]
		}
	}
	return nil
}
func (g *readGraph) redact(item map[string]any, r any) bool {
	for _, field := range []string{"subject", "issuer", "submitter"} {
		v := g.alias(item[field], env(r)["space"])
		if v == nil {
			return false
		}
		item[field] = v
	}
	p := obj(item["perspective"])
	v := g.alias(p["principal"], env(r)["space"])
	if v == nil {
		return false
	}
	p["principal"] = v
	item["ref"] = nil
	item["representation_ref"] = nil
	item["authority_receipt"] = nil
	item["source_refs"] = []any{}
	item["incompatible_with"] = []any{}
	for _, pol := range []string{"support", "oppose"} {
		obj(item[pol])["witness_roots"] = []any{}
		coverage := obj(obj(item[pol])["corpus_coverage"])
		if coverage["kind"] == "declared" {
			obj(item[pol])["corpus_coverage"] = map[string]any{"kind": "unknown"}
		}
	}
	return true
}
func (g *readGraph) freshness(r any) (any, string) {
	horizon := g.q["usable_until"]
	duration := obj(g.s.domain(r)["freshness_default"])
	if horizon == nil && duration["kind"] != "duration" {
		return nil, "not_applicable"
	}
	if horizon == nil {
		if env(r)["confirmed_at"] == nil {
			return nil, "stale"
		}
		horizon = addSeconds(env(r)["confirmed_at"].(string), duration["seconds"].(int64))
	}
	if horizon == nil || g.q["now"].(string) >= horizon.(string) {
		return horizon, "stale"
	}
	return horizon, "fresh"
}

// addSeconds uses civil calendar arithmetic only, with no clock or timezone IO.
func addSeconds(stamp string, seconds int64) any {
	n := func(a, b int) int64 { v, _ := strconv.ParseInt(stamp[a:b], 10, 64); return v }
	y, m, d := n(0, 4), n(5, 7), n(8, 10)
	// Gregorian days since year 1; bounded years keep arithmetic exact.
	daysBefore := func(year int64) int64 { z := year - 1; return 365*z + z/4 - z/100 + z/400 }
	monthDays := func(year, month int64) int64 {
		a := []int64{31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}
		if month == 2 && (year%4 == 0 && (year%100 != 0 || year%400 == 0)) {
			return 29
		}
		return a[month-1]
	}
	days := daysBefore(y) + d - 1
	for month := int64(1); month < m; month++ {
		days += monthDays(y, month)
	}
	total := days*86400 + n(11, 13)*3600 + n(14, 16)*60 + n(17, 19)
	maxStamp := daysBefore(10000)*86400 - 1
	if seconds < 0 || seconds > maxStamp-total {
		return nil
	}
	total += seconds
	days = total / 86400
	clock := total % 86400
	lo, hi := int64(1), int64(10000)
	for lo+1 < hi {
		mid := (lo + hi) / 2
		if daysBefore(mid) <= days {
			lo = mid
		} else {
			hi = mid
		}
	}
	y = lo
	days -= daysBefore(y)
	m = 1
	for days >= monthDays(y, m) {
		days -= monthDays(y, m)
		m++
	}
	return fmt.Sprintf("%04d-%02d-%02dT%02d:%02d:%02dZ", y, m, days+1, clock/3600, clock/60%60, clock%60)
}

// SetAvailability applies only the owner's predeclared coarse availability
// stimulus. It changes no records, cuts, lineage, or logical evidence.
func (s *State) SetAvailability(op map[string]any) (map[string]any, *Refusal) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, r := CanonicalJSON(op); r != nil {
		return nil, r
	}
	if !s.schemas.roots[packageSchema+"vector"].properties["operations"].items.matches(op, nil) || op["op"] != "set_availability" {
		return nil, refusal(InvalidShape)
	}
	if op["actor"] != s.policy()["owner"] || s.policy()["availability_disclosure"] != "coarse_unavailable" {
		return nil, refusal(NotAuthorized)
	}
	if !validStamp(op["at"]) {
		return nil, refusal(InvalidTime)
	}
	h, r := s.nextHandle()
	if r != nil {
		return nil, r
	}
	s.policy()["public_availability"] = op["state"]
	return map[string]any{"type": "receipt", "operation": "set_availability", "outcome": "availability_changed", "receipt_handle": h, "refs": []any{}, "custody": []any{}, "erasure_status": nil}, nil
}

// reviewImpact preserves explicit review dependencies after their inputs become
// historical, without resurrecting resolved sufficient-support dirty causes.
func (g *readGraph) reviewImpact(revision any) map[string]bool {
	result := map[string]bool{}
	if !g.allowed(revision) || !g.allowed(g.index[refKey(body(revision)["target"])]) {
		return result
	}
	h := g.before(obj(env(revision)["recorded"])["sequence"].(int64))
	reached := map[string]bool{refKey(body(revision)["target"]): false}
	for again := true; again; {
		again = false
		for _, r := range h.records {
			b := body(r)
			if b["role"] != "sufficient_support" && b["role"] != "review_on_change" || !h.ruleEligible(r, false) {
				continue
			}
			hit, review := false, false
			inputs := []any{ref(r)}
			if b["check"] != nil {
				inputs = append(inputs, b["check"])
			}
			for _, p := range arr(b["premises"]) {
				m := obj(p)
				if m["kind"] == "source" {
					inputs = append(inputs, m["source"])
				} else {
					inputs = append(inputs, obj(m["literal"])["assertion"])
				}
			}
			for _, v := range inputs {
				value, ok := reached[refKey(v)]
				if ok {
					hit = true
					review = review || value
				}
			}
			if !hit {
				continue
			}
			review = review || b["role"] == "review_on_change"
			target := refKey(obj(b["target"])["assertion"])
			old, ok := reached[target]
			if !ok || review && !old {
				reached[target] = review
				again = true
			}
		}
	}
	for k, v := range reached {
		if v {
			result[k] = true
		}
	}
	return result
}
