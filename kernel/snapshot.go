package kernel

func (s *State) validateSnapshot() *Refusal {
	if badVersion(s.snapshot) {
		return refusal(InvalidDomainValue)
	}
	records := arr(s.snapshot["records"])
	index := recordIndex(records)
	if len(index) != len(records) {
		return refusal(DuplicateRecord)
	}
	policy, runtime := s.policy(), s.runtime()
	for _, field := range []string{"memory_cut", "erasure_generation", "hidden_work"} {
		if runtime[field].(int64) < 0 {
			return refusal(InvalidShape)
		}
	}
	for _, field := range []string{"max_records", "max_fan_in", "max_payload_bytes"} {
		if obj(policy["limits"])[field].(int64) < 0 {
			return refusal(InvalidShape)
		}
	}
	for _, v := range obj(obj(policy["limits"])["read"]) {
		if v.(int64) < 0 {
			return refusal(InvalidShape)
		}
	}
	domains := map[string]bool{}
	for _, v := range arr(s.snapshot["domain_schemas"]) {
		d := obj(v)
		k := refKey(d)
		if domains[k] {
			return refusal(InvalidDomainValue)
		}
		domains[k] = true
		if d["version"].(int64) < 1 {
			return refusal(InvalidDomainValue)
		}
		names := map[string]bool{}
		for _, f := range arr(d["fields"]) {
			m := obj(f)
			name := m["name"].(string)
			if names[name] {
				return refusal(InvalidDomainValue)
			}
			names[name] = true
			if (m["type"] == "string_set") != (m["equality"] == "set") {
				return refusal(InvalidDomainValue)
			}
		}
		for _, incompatibility := range arr(d["incompatibilities"]) {
			m := obj(incompatibility)
			if !names[m["field"].(string)] || (len(arr(m["same"])) != 4 || !equalJSON(set(arr(m["same"])), []any{"perspective", "slot", "space", "subject"})) {
				return refusal(InvalidDomainValue)
			}
		}
		for _, name := range arr(obj(d["cardinality"])["slot_fields"]) {
			if !names[name.(string)] {
				return refusal(InvalidDomainValue)
			}
		}
	}
	facts := map[string]bool{}
	for _, v := range arr(policy["lineage_facts"]) {
		f := obj(v)
		k := refKey(f["output"])
		if facts[k] || !ordered(f["inputs"]) || f["kind"] == "direct" && len(arr(f["inputs"])) != 0 {
			return refusal(InvalidReference)
		}
		facts[k] = true
	}
	sequences := map[int64]bool{}
	for _, r := range records {
		e := env(r)
		seq := obj(e["recorded"])["sequence"].(int64)
		if seq < 1 || seq > runtime["memory_cut"].(int64) || sequences[seq] {
			return refusal(InvalidTime)
		}
		sequences[seq] = true
		if refusal := s.recordContract(r, index, obj(e["recorded"])["at"]); refusal != nil {
			return refusal
		}
		f := s.fact(r)
		if f["complete"] == true && !equalJSON(e["lineage"], f["inputs"]) || f["complete"] != true && e["lineage"] != "unknown" {
			return refusal(InvalidReference)
		}
		if e["issuer"] == e["submitter"] && e["representation_ref"] != nil || e["issuer"] != e["submitter"] && (e["representation_ref"] == nil || obj(e["representation_ref"])["checked"] != true) {
			return refusal(RepresentationInvalid)
		}
	}
	for _, r := range records {
		if env(r)["kind"] != "revision" {
			continue
		}
		b := body(r)
		target := index[refKey(b["target"])]
		relation := b["relation"]
		if relation != "challenge" && env(r)["issuer"] != env(target)["issuer"] {
			return refusal(RepresentationInvalid)
		}
		if obj(env(target)["recorded"])["sequence"].(int64) >= obj(env(r)["recorded"])["sequence"].(int64) {
			return refusal(InvalidReference)
		}
		replaces := relation == "replace" || relation == "correct"
		if replaces != (b["replacement"] != nil) || relation == "availability" && (env(target)["kind"] != "source" || b["availability"] == nil) || relation != "availability" && b["availability"] != nil {
			return refusal(InvalidDomainValue)
		}
		if replaces {
			replacement := index[refKey(b["replacement"])]
			if env(replacement)["id"] != env(target)["id"] || env(target)["version"].(int64) == int64(^uint64(0)>>1) || env(replacement)["version"].(int64) != env(target)["version"].(int64)+1 || s.sequence(replacement) != s.sequence(target) {
				return refusal(InvalidDomainValue)
			}
		}
	}
	heads := map[string]bool{}
	for _, r := range s.currentRecords(records) {
		if env(r)["kind"] != "assertion" || body(r)["statement_kind"] == "decision_record" || obj(s.domain(r)["cardinality"])["mode"] != "single" {
			continue
		}
		k := s.sequence(r)
		if heads[k] {
			return refusal(VersionConflict)
		}
		heads[k] = true
	}
	graph := map[string][]string{}
	events := map[string]bool{}
	for _, v := range arr(policy["authority_events"]) {
		e := obj(v)
		k := refKey(e["receipt"])
		if events[k] || env(index[k])["kind"] != "source" || !ordered(e["predecessors"]) {
			return refusal(InvalidReference)
		}
		events[k] = true
		for _, p := range arr(e["predecessors"]) {
			graph[k] = append(graph[k], refKey(p))
		}
	}
	for _, edges := range graph {
		for _, p := range edges {
			if !events[p] {
				return refusal(InvalidReference)
			}
		}
	}
	if graphCycle(graph) || graphCycle(s.supportGraph(records)) {
		return refusal(Cycle)
	}
	for _, r := range records {
		if body(r)["statement_kind"] == "decision_record" {
			receipt := body(r)["authority_receipt"]
			e := s.event(receipt)
			if e == nil || e["canonical"] != true || e["issuer"] != env(r)["issuer"] || env(index[refKey(receipt)])["kind"] != "source" {
				return refusal(AuthorityReceiptRequired)
			}
		}
	}
	if !ordered(runtime["committed_cuts"]) || !contains(runtime["committed_cuts"], runtime["memory_cut"]) {
		return refusal(InvalidTime)
	}
	for _, cut := range arr(runtime["committed_cuts"]) {
		if cut.(int64) < 0 || cut.(int64) > runtime["memory_cut"].(int64) {
			return refusal(InvalidTime)
		}
	}
	for _, v := range arr(runtime["dirty_causes"]) {
		m := obj(v)
		if env(index[refKey(m["assertion"])])["kind"] != "assertion" || env(index[refKey(m["revision"])])["kind"] != "revision" || !contains(runtime["dirty"], m["assertion"]) {
			return refusal(InvalidReference)
		}
	}
	for _, v := range arr(runtime["dirty"]) {
		found := false
		for _, c := range arr(runtime["dirty_causes"]) {
			if equalJSON(obj(c)["assertion"], v) {
				found = true
			}
		}
		if !found {
			return refusal(InvalidReference)
		}
	}
	for _, name := range []string{"dirty", "erased", "fences"} {
		if !ordered(runtime[name]) {
			return refusal(InvalidReference)
		}
		if name == "dirty" {
			for _, v := range arr(runtime[name]) {
				if index[refKey(v)] == nil {
					return refusal(InvalidReference)
				}
			}
		}
	}
	for _, c := range arr(runtime["custody"]) {
		for _, v := range arr(obj(c)["inputs"]) {
			if index[refKey(v)] == nil {
				return refusal(InvalidReference)
			}
		}
	}
	identities := map[string]bool{}
	for _, v := range arr(runtime["idempotency"]) {
		m := obj(v)
		k := key([]any{m["actor"], m["space"], m["key"]})
		if identities[k] {
			return refusal(IdempotencyConflict)
		}
		identities[k] = true
		parsed, r := DecodeJSON([]byte(m["canonical_request"].(string)))
		if r != nil || obj(parsed) == nil || key(parsed) != m["canonical_request"] {
			return refusal(InvalidReference)
		}
		if r := s.replayBinding(m, obj(parsed)); r != nil {
			return r
		}
		if !validHandle(obj(m["receipt"])["receipt_handle"].(string)) {
			return refusal(InvalidReference)
		}
		for _, v := range arr(obj(m["receipt"])["refs"]) {
			if index[refKey(v)] == nil {
				return refusal(InvalidReference)
			}
		}
	}
	return nil
}

// The replay ledger pins a complete authenticated intent, not arbitrary JSON.
// Other finite operations can have entries in an imported complete snapshot;
// their operation-specific binding checks belong to their owning implementation.
func (s *State) replayBinding(entry, intent map[string]any) *Refusal {
	kind := intent["op"]
	receipt := obj(entry["receipt"])
	if kind != receipt["operation"] {
		return refusal(InvalidReference)
	}
	if kind != "admit" && kind != "revise" {
		return nil
	}
	context := obj(intent["context"])
	if context == nil || context["actor"] != entry["actor"] {
		return refusal(InvalidReference)
	}
	if _, exists := context["at"]; exists {
		return refusal(InvalidReference)
	}
	if _, exists := intent["idempotency_key"]; exists {
		return refusal(InvalidReference)
	}
	operation := copyJSON(intent).(map[string]any)
	obj(operation["context"])["at"] = "0001-01-01T00:00:00Z"
	operation["idempotency_key"] = entry["key"]
	if !s.schemas.roots[packageSchema+"vector"].properties["operations"].items.matches(operation, nil) || badVersion(operation) {
		return refusal(InvalidReference)
	}
	batch := batchProposals(operation)
	if len(batch) == 0 || env(batch[0])["space"] != entry["space"] {
		return refusal(InvalidReference)
	}
	refs := []any{}
	for _, r := range batch {
		refs = append(refs, ref(r))
	}
	sortRefs(refs)
	outcome := "admitted"
	if kind == "revise" {
		outcome = "revised"
		if body(operation["revision"])["relation"] == "challenge" {
			outcome = "challenged"
		}
	}
	if !equalJSON(receipt["refs"], refs) || receipt["outcome"] != outcome {
		return refusal(InvalidReference)
	}
	return nil
}
