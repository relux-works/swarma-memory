package kernel

import "sort"

func (s *State) event(receipt any) map[string]any {
	for _, v := range arr(s.policy()["authority_events"]) {
		if equalJSON(obj(v)["receipt"], receipt) {
			return obj(v)
		}
	}
	return nil
}

// precedes restricts vertices AND edges to the deciding issuer before searching.
// In particular, it never contracts a path through a foreign issuer.
func (s *State) precedes(issuer, earlier, later any) bool {
	if equalJSON(earlier, later) {
		return false
	}
	events := map[string]map[string]any{}
	for _, v := range arr(s.policy()["authority_events"]) {
		m := obj(v)
		if m["issuer"] == issuer {
			events[refKey(m["receipt"])] = m
		}
	}
	target := refKey(earlier)
	start := refKey(later)
	if events[target] == nil || events[start] == nil {
		return false
	}
	seen := map[string]bool{}
	stack := []string{start}
	for len(stack) > 0 {
		k := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if seen[k] {
			continue
		}
		seen[k] = true
		for _, p := range arr(events[k]["predecessors"]) {
			next := refKey(p)
			if events[next] == nil {
				continue
			}
			if next == target {
				return true
			}
			stack = append(stack, next)
		}
	}
	return false
}
func (s *State) eligibleReceipt(receipt, issuer any, ctx map[string]any, index map[string]any) bool {
	if receipt == nil {
		return false
	}
	event := s.event(receipt)
	source := index[refKey(receipt)]
	if event == nil || event["canonical"] != true || event["issuer"] != issuer || env(source)["kind"] != "source" {
		return false
	}
	e := env(source)
	c := obj(ctx["retention_context"])
	d := obj(e["disclosure"])
	if !contains(d["audiences"], c["audience"]) || !contains(d["purposes"], c["purpose"]) {
		return false
	}
	for _, right := range []string{"read", "use"} {
		if !s.grant(ctx["actor"], e["space"], e["id"], c["audience"], c["purpose"], right, true) {
			return false
		}
	}
	return !contains(s.runtime()["erased"], receipt)
}
func (s *State) currentRecords(records []any) []any {
	historical := map[string]bool{}
	for _, r := range records {
		if env(r)["kind"] == "revision" && body(r)["relation"] != "challenge" {
			historical[refKey(body(r)["target"])] = true
		}
	}
	out := []any{}
	for _, r := range records {
		if !historical[refKey(ref(r))] && env(r)["kind"] != "revision" {
			out = append(out, r)
		}
	}
	return out
}
func (s *State) head(target any, records []any, ctx map[string]any) any {
	if body(target)["statement_kind"] == "decision_record" {
		candidates := []any{}
		index := recordIndex(records)
		for _, r := range records {
			if env(r)["kind"] == "assertion" && s.sequence(r) == s.sequence(target) && s.eligibleReceipt(body(r)["authority_receipt"], env(r)["issuer"], ctx, index) {
				candidates = append(candidates, r)
			}
		}
		maxima := []any{}
		for _, r := range candidates {
			dominated := false
			for _, other := range candidates {
				if s.precedes(env(r)["issuer"], body(r)["authority_receipt"], body(other)["authority_receipt"]) {
					dominated = true
					break
				}
			}
			if !dominated {
				maxima = append(maxima, ref(r))
			}
		}
		if len(maxima) != 1 {
			return nil
		}
		return maxima[0]
	}
	index := recordIndex(records)
	sequence := s.sequence(target)
	var resolve func(any, map[string]bool) string
	resolve = func(r any, seen map[string]bool) string {
		if r == nil {
			return ""
		}
		k := refKey(ref(r))
		if seen[k] {
			return ""
		}
		seen[k] = true
		if env(r)["kind"] == "revision" {
			return resolve(index[refKey(body(r)["target"])], seen)
		}
		return s.sequence(r)
	}
	tokens := map[string]any{}
	for _, r := range records {
		if env(r)["kind"] != "revision" && s.sequence(r) == sequence {
			tokens[refKey(ref(r))] = ref(r)
		}
	}
	revisions := []any{}
	for _, r := range records {
		if env(r)["kind"] == "revision" && body(r)["relation"] != "challenge" && resolve(r, map[string]bool{}) == sequence {
			revisions = append(revisions, r)
		}
	}
	sort.Slice(revisions, func(i, j int) bool {
		return obj(env(revisions[i])["recorded"])["sequence"].(int64) < obj(env(revisions[j])["recorded"])["sequence"].(int64)
	})
	for _, r := range revisions {
		b := body(r)
		delete(tokens, refKey(b["target"]))
		for k, v := range tokens {
			if env(index[refKey(v)])["kind"] == "revision" {
				delete(tokens, k)
			}
		}
		token := b["replacement"]
		if token == nil {
			token = ref(r)
		}
		tokens[refKey(token)] = token
	}
	if len(tokens) != 1 {
		return nil
	}
	for _, v := range tokens {
		return v
	}
	return nil
}
func (s *State) revisionContract(op map[string]any, existing, index map[string]any) *Refusal {
	revision, replacement := op["revision"], op["replacement"]
	e, b := env(revision), body(revision)
	relation := b["relation"]
	target := existing[refKey(b["target"])]
	if target == nil {
		return refusal(InvalidReference)
	}
	if relation != "challenge" && e["issuer"] != env(target)["issuer"] {
		return refusal(RepresentationInvalid)
	}
	if e["subject"] != env(target)["subject"] || e["space"] != env(target)["space"] {
		return refusal(InvalidDomainValue)
	}
	replaces := relation == "replace" || relation == "correct"
	if replaces != (replacement != nil) || replaces != (b["replacement"] != nil) || relation == "availability" && (env(target)["kind"] != "source" || b["availability"] == nil) || relation != "availability" && b["availability"] != nil {
		return refusal(InvalidDomainValue)
	}
	if replaces {
		re := env(replacement)
		if !equalJSON(b["replacement"], ref(replacement)) || re["id"] != env(target)["id"] || env(target)["version"].(int64) == int64(^uint64(0)>>1) || re["version"].(int64) != env(target)["version"].(int64)+1 || s.sequence(replacement) != s.sequence(target) {
			return refusal(InvalidDomainValue)
		}
		if body(replacement)["statement_kind"] == "decision_record" && !s.eligibleReceipt(body(replacement)["authority_receipt"], re["issuer"], obj(op["context"]), index) {
			return refusal(AuthorityReceiptRequired)
		}
	}
	if relation != "challenge" {
		head := s.head(target, arr(s.snapshot["records"]), obj(op["context"]))
		if head == nil || !equalJSON(head, op["expected_version"]) || env(existing[refKey(head)])["kind"] != "revision" && !equalJSON(head, b["target"]) {
			return refusal(VersionConflict)
		}
	}
	if replaces && body(target)["statement_kind"] == "decision_record" {
		receipt := body(replacement)["authority_receipt"]
		if !equalJSON(receipt, b["authority_receipt"]) || !s.precedes(env(target)["issuer"], body(target)["authority_receipt"], receipt) {
			return refusal(AuthorityReceiptRequired)
		}
	}
	return nil
}
func (s *State) markDirty(runtime map[string]any, revision any, records []any) {
	changed := map[string]bool{refKey(body(revision)["target"]): true}
	affected := map[string]any{}
	for again := true; again; {
		again = false
		for _, rule := range s.currentRecords(records) {
			b := body(rule)
			if env(rule)["kind"] != "justification" || b["role"] != "sufficient_support" && b["role"] != "review_on_change" {
				continue
			}
			target := obj(b["target"])["assertion"]
			k := refKey(target)
			if affected[k] != nil {
				continue
			}
			hit := changed[refKey(ref(rule))] || b["check"] != nil && changed[refKey(b["check"])]
			for _, premise := range arr(b["premises"]) {
				p := obj(premise)
				v := p["source"]
				if p["kind"] == "assertion" {
					v = obj(p["literal"])["assertion"]
				}
				if changed[refKey(v)] {
					hit = true
				}
			}
			if hit {
				affected[k] = target
				changed[k] = true
				again = true
			}
		}
	}
	for _, target := range affected {
		runtime["dirty"] = append(arr(runtime["dirty"]), target)
		runtime["dirty_causes"] = append(arr(runtime["dirty_causes"]), map[string]any{"assertion": target, "revision": ref(revision)})
	}
	runtime["dirty"] = set(arr(runtime["dirty"]))
	runtime["dirty_causes"] = set(arr(runtime["dirty_causes"]))
}
