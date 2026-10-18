package kernel

import "sort"

func contentValue(r any, name any) any {
	for _, v := range arr(body(r)["content"]) {
		if obj(v)["field"] == name {
			return obj(v)["value"]
		}
	}
	return nil
}
func (s *State) sequence(r any) string {
	e := env(r)
	parts := []any{e["issuer"], e["subject"], e["space"], e["schema"], e["perspective"], body(r)["slot"]}
	if obj(s.domain(r)["cardinality"])["mode"] == "multi" {
		parts = append(parts, e["id"])
	}
	if e["kind"] != "assertion" {
		parts = []any{e["id"], e["issuer"], e["subject"], e["space"], e["kind"], e["perspective"]}
	}
	return key(parts)
}

// recordContract accumulates only this K-API-2 class, then chooses the first
// field in lexical order. Batch order is supplied by the caller's outer loop.
func (s *State) recordContract(r any, index map[string]any, at any) *Refusal {
	e, b := env(r), body(r)
	problems := map[string]RefusalCode{}
	report := func(path string, code RefusalCode) {
		if _, exists := problems[path]; !exists {
			problems[path] = code
		}
	}
	if e["version"].(int64) < 1 {
		report("/envelope/version", InvalidDomainValue)
	}
	if (e["kind"] == "assertion") != (e["schema"] != nil) {
		report("/envelope/schema", InvalidDomainValue)
	}
	perspective := obj(e["perspective"])
	if perspective["kind"] != "team" && perspective["principal"] != e["issuer"] {
		report("/envelope/perspective", InvalidDomainValue)
	}
	if perspective["kind"] == "team" {
		admitted := false
		for _, g := range arr(s.policy()["grants"]) {
			if obj(g)["principal"] == e["issuer"] && obj(g)["space"] == e["space"] && contains(obj(g)["rights"], "admit") {
				admitted = true
			}
		}
		if !admitted {
			report("/envelope/perspective", InvalidDomainValue)
		}
	}
	if e["admission_class"] == "self_declaration" || b["statement_kind"] == "self_declaration" {
		bound := false
		for _, binding := range arr(s.policy()["subject_principals"]) {
			if obj(binding)["subject"] == e["subject"] && obj(binding)["principal"] == e["issuer"] {
				bound = true
			}
		}
		if !bound {
			report("/envelope/subject", InvalidDomainValue)
		}
		if perspective["kind"] != "own" || perspective["principal"] != e["issuer"] {
			report("/envelope/perspective", InvalidDomainValue)
		}
	}
	fact := s.fact(r)
	if fact == nil {
		report("/envelope/lineage", InvalidReference)
	} else {
		for _, v := range arr(fact["inputs"]) {
			if index[refKey(v)] == nil {
				report("/envelope/lineage", InvalidReference)
			}
		}
		if fact["kind"] == "model" && e["kind"] == "assertion" && (e["admission_class"] != "semantic_inference" || b["statement_kind"] != "proposal" && b["statement_kind"] != "assessment_summary") {
			report("/envelope/admission_class", InvalidDomainValue)
		}
	}
	for _, field := range []string{"audiences", "purposes", "field_classes", "declassification"} {
		if !ordered(obj(e["disclosure"])[field]) {
			report("/envelope/disclosure/"+field, InvalidDomainValue)
		}
	}
	if lineage, ok := e["lineage"].([]any); ok && !ordered(lineage) {
		report("/envelope/lineage", InvalidDomainValue)
	}
	switch e["kind"] {
	case "assertion":
		d := s.domain(r)
		if d == nil {
			report("/envelope/schema", UnknownSchema)
			break
		}
		if b["statement_kind"] != d["statement_kind"] {
			report("/body/statement_kind", InvalidDomainValue)
		}
		fields := map[string]map[string]any{}
		for _, v := range arr(d["fields"]) {
			f := obj(v)
			fields[f["name"].(string)] = f
		}
		previous := ""
		seen := map[string]bool{}
		for i, v := range arr(b["content"]) {
			f := obj(v)
			name := f["field"].(string)
			declaration := fields[name]
			if declaration == nil || i > 0 && name <= previous {
				report("/body/content", InvalidDomainValue)
			}
			previous = name
			seen[name] = true
			if declaration == nil {
				continue
			}
			value := f["value"]
			valid := false
			switch declaration["type"] {
			case "string":
				_, valid = value.(string)
			case "integer":
				_, valid = value.(int64)
			case "boolean":
				_, valid = value.(bool)
			case "string_set":
				a, ok := value.([]any)
				valid = ok && ordered(a)
				for _, item := range a {
					if _, ok := item.(string); !ok {
						valid = false
					}
				}
			}
			if !valid {
				report("/body/content", InvalidDomainValue)
			}
		}
		for name, f := range fields {
			if f["required"] == true && !seen[name] {
				report("/body/content", InvalidDomainValue)
			}
		}
		slot := []any{}
		cardinality := obj(d["cardinality"])
		if cardinality["mode"] == "single" {
			for _, f := range arr(cardinality["slot_fields"]) {
				v := contentValue(r, f)
				if v == nil {
					report("/body/slot", InvalidDomainValue)
				}
				slot = append(slot, v)
			}
		}
		if b["slot"] != key(slot) {
			report("/body/slot", InvalidDomainValue)
		}
	case "source":
		// Retention-admission references name external adapter evidence, not records.
		// The fixture policy supplies the trusted fact; retain is independently checked.
		if b["excerpt"] != nil && b["retention_admission"] == nil {
			report("/body/retention_admission", InvalidReference)
		}
	case "assessment":
		pins := obj(b["pins"])
		if index[refKey(pins["subject"])] == nil {
			report("/body/pins/subject", InvalidReference)
		}
		if b["target"] != nil {
			target := obj(b["target"])["assertion"]
			if env(index[refKey(target)])["kind"] != "assertion" || !equalJSON(target, pins["subject"]) {
				report("/body/target", InvalidReference)
			}
		}
		for _, v := range arr(b["sources"]) {
			if env(index[refKey(v)])["kind"] != "source" {
				report("/body/sources", InvalidReference)
			}
		}
		if (b["executor"] == "model" || fact["kind"] == "model") && b["check_kind"] != "semantic_review" {
			report("/body/check_kind", AssessmentKindInvalid)
		}
	case "justification":
		if env(index[refKey(obj(b["target"])["assertion"])])["kind"] != "assertion" {
			report("/body/target", InvalidReference)
		}
		if b["check"] != nil && env(index[refKey(b["check"])])["kind"] != "assessment" {
			report("/body/check", InvalidReference)
		}
		for _, p := range arr(b["premises"]) {
			m := obj(p)
			v := m["source"]
			if m["kind"] == "assertion" {
				v = obj(m["literal"])["assertion"]
			}
			input := index[refKey(v)]
			if env(input)["kind"] != m["kind"] {
				report("/body/premises", InvalidReference)
			} else if env(input)["space"] != e["space"] {
				report("/body/premises", CrossScope)
			}
		}
	case "revision":
		if index[refKey(b["target"])] == nil {
			report("/body/target", InvalidReference)
		}
		if b["replacement"] != nil && index[refKey(b["replacement"])] == nil {
			report("/body/replacement", InvalidReference)
		}
	}
	for path, value := range map[string]any{"/envelope/confirmed_at": e["confirmed_at"], "/envelope/recorded/at": obj(e["recorded"])["at"], "/envelope/disclosure/retain_until": obj(e["disclosure"])["retain_until"], "/body/usable_until": b["usable_until"]} {
		if value != nil && !validStamp(value) {
			report(path, InvalidTime)
		}
	}
	validity := obj(e["valid"])
	if validity["kind"] == "known" {
		if !validStamp(validity["from"]) {
			report("/envelope/valid/from", InvalidTime)
		}
		if to := validity["to"]; to != nil && (!validStamp(to) || validStamp(validity["from"]) && to.(string) <= validity["from"].(string)) {
			report("/envelope/valid/to", InvalidTime)
		}
	}
	paths := make([]string, 0, len(problems))
	for p := range problems {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	if len(paths) > 0 {
		return refusal(problems[paths[0]])
	}
	return nil
}
func (s *State) ruleContract(r any, index map[string]any, at any) *Refusal {
	if env(r)["kind"] != "justification" {
		return nil
	}
	b := body(r)
	if len(arr(b["premises"])) == 0 {
		return refusal(RuleUnqualified)
	}
	if b["role"] != "sufficient_support" {
		if b["rule_kind"] != "declared_rationale" || b["check"] != nil {
			return refusal(RuleUnqualified)
		}
		return nil
	}
	if b["rule_kind"] != "checked_entailment" {
		return refusal(RuleUnqualified)
	}
	for _, p := range arr(b["premises"]) {
		if obj(p)["kind"] != "assertion" {
			return refusal(RuleUnqualified)
		}
	}
	cert := index[refKey(b["check"])]
	c := body(cert)
	pins := obj(c["pins"])
	policy := obj(s.policy()["evidence"])
	if c["check_kind"] != "formal_entailment" || c["executor"] != "deterministic" || c["result"] != "pass" || c["target"] != nil || !equalJSON(pins["subject"], ref(r)) || !equalJSON(pins["rule"], b["rule"]) || !equalJSON(pins["policy"], policy["policy_pin"]) || !equalJSON(pins["environment"], policy["environment_pin"]) || env(cert)["context"] != env(r)["context"] {
		return refusal(RuleUnqualified)
	}
	for _, r := range index {
		if env(r)["kind"] == "revision" && body(r)["relation"] != "challenge" && equalJSON(body(r)["target"], b["check"]) {
			return refusal(RuleUnqualified)
		}
	}
	if t := c["usable_until"]; t != nil && validStamp(at) && at.(string) >= t.(string) {
		return refusal(RuleUnqualified)
	}
	return nil
}
func (s *State) supportGraph(records []any) map[string][]string {
	graph := map[string][]string{}
	for _, r := range records {
		if env(r)["kind"] != "justification" || body(r)["role"] != "sufficient_support" {
			continue
		}
		b := body(r)
		target := refKey(obj(b["target"])["assertion"])
		for _, p := range arr(b["premises"]) {
			if obj(p)["kind"] == "assertion" {
				graph[target] = append(graph[target], refKey(obj(obj(p)["literal"])["assertion"]))
			}
		}
	}
	return graph
}
func graphCycle(graph map[string][]string) bool {
	state := map[string]int{}
	var visit func(string) bool
	visit = func(k string) bool {
		if state[k] == 1 {
			return true
		}
		if state[k] == 2 {
			return false
		}
		state[k] = 1
		for _, next := range graph[k] {
			if visit(next) {
				return true
			}
		}
		state[k] = 2
		return false
	}
	keys := make([]string, 0, len(graph))
	for k := range graph {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if visit(k) {
			return true
		}
	}
	return false
}
