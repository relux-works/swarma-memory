package kernel

// Write executes admit, admit_raw or revise from exact decoded JSON. Unsupported
// operations are refused without attempting reads or evaluation. Each validation
// pass covers the entire batch before the next K-API-2 class is considered.
func (s *State) Write(input map[string]any) (map[string]any, *Refusal) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, r := CanonicalJSON(input); r != nil {
		return nil, r
	}
	op := copyJSON(input).(map[string]any)
	kind, _ := op["op"].(string)
	if kind != "admit" && kind != "admit_raw" && kind != "revise" {
		return nil, refusal(UnsupportedOperation)
	}
	node := s.schemas.roots[packageSchema+"vector"].properties["operations"].items
	if !node.matches(op, nil) {
		return nil, refusal(InvalidShape)
	}
	if kind == "admit_raw" {
		raw, r := DecodeJSON([]byte(op["raw_json"].(string)))
		if r != nil {
			return nil, r
		}
		m := obj(raw)
		if len(m) != 1 || m["proposals"] == nil {
			return nil, refusal(InvalidShape)
		}
		op["op"] = "admit"
		op["proposals"] = m["proposals"]
		delete(op, "raw_json")
		if !node.matches(op, nil) {
			return nil, refusal(InvalidShape)
		}
	}
	if op["expected_generation"].(int64) < 0 {
		return nil, refusal(InvalidShape)
	}
	ctx := obj(op["context"])
	var batch []any
	if op["op"] == "revise" {
		if op["replacement"] != nil {
			batch = append(batch, op["replacement"])
		}
		batch = append(batch, op["revision"])
		if env(op["revision"])["kind"] != "revision" {
			return nil, refusal(InvalidShape)
		}
	} else {
		batch = arr(op["proposals"])
		for _, r := range batch {
			if env(r)["kind"] == "revision" {
				return nil, refusal(InvalidShape)
			}
		}
	}
	if len(batch) == 0 {
		return nil, refusal(InvalidShape)
	}
	payload, _ := CanonicalJSON(batchProposals(op))
	space := env(batch[0])["space"]
	existing := recordIndex(arr(s.snapshot["records"]))
	hypothetical := recordIndex(arr(s.snapshot["records"]))
	for _, r := range batch {
		hypothetical[refKey(ref(r))] = r
	}
	// Rights and all currently resolved retention inputs precede replay and content.
	if !s.operationRight(ctx["actor"], space, op["op"].(string)) {
		return nil, refusal(NotAuthorized)
	}
	for _, r := range batch {
		if !equalJSON(env(r)["space"], space) {
			return nil, refusal(NotAuthorized)
		}
		if !s.retention(r, ctx, hypothetical, map[string]bool{}) {
			return nil, refusal(NotAuthorized)
		}
	}
	intent := copyJSON(op).(map[string]any)
	delete(intent, "idempotency_key")
	delete(obj(intent["context"]), "at")
	canonical := key(intent)
	for _, x := range arr(s.runtime()["idempotency"]) {
		entry := obj(x)
		if entry["actor"] != ctx["actor"] || entry["space"] != space || entry["key"] != op["idempotency_key"] {
			continue
		}
		for _, v := range arr(obj(entry["receipt"])["refs"]) {
			r := existing[refKey(v)]
			if r == nil || !s.retention(r, ctx, existing, map[string]bool{}) {
				return nil, refusal(NotAuthorized)
			}
		}
		if entry["canonical_request"] != canonical {
			return nil, refusal(IdempotencyConflict)
		}
		return copyJSON(entry["receipt"]).(map[string]any), nil
	}
	relation := "admit"
	if op["op"] == "revise" {
		relation = body(op["revision"])["relation"].(string)
	}
	for _, r := range batch {
		if !s.representation(env(r), ctx["actor"], relation) {
			return nil, refusal(RepresentationInvalid)
		}
		if !s.reviewed(r) {
			return nil, refusal(Quarantined)
		}
	}
	if op["expected_generation"] != s.runtime()["erasure_generation"] {
		return nil, refusal(StaleGeneration)
	}
	if obj(s.runtime()["restore"])["status"] == "fenced" {
		return nil, refusal(ErasureFenced)
	}
	for _, r := range batch {
		if s.fenced(r, hypothetical, map[string]bool{}) {
			return nil, refusal(ErasureFenced)
		}
	}
	// Stamp private candidates, retaining proposal order (replacement, then revision).
	cut := s.runtime()["memory_cut"].(int64)
	sequenceOverflow := int64(len(batch)) > maxJSONInteger-cut
	for i, r := range batch {
		e := env(r)
		e["submitter"] = ctx["actor"]
		e["admission_class"] = ctx["admission_class"]
		e["recorded"] = map[string]any{"sequence": cut + int64(i) + 1, "at": ctx["at"]}
		if e["representation_ref"] != nil {
			obj(e["representation_ref"])["checked"] = true
		}
	}
	for _, r := range batch {
		if f := s.fact(r); f != nil {
			if f["complete"] == true {
				env(r)["lineage"] = copyJSON(f["inputs"])
			} else {
				env(r)["lineage"] = "unknown"
			}
		}
		if refusal := s.recordContract(r, hypothetical, ctx["at"]); refusal != nil {
			return nil, refusal
		}
	}
	if badVersion(op["expected_version"]) {
		return nil, refusal(InvalidDomainValue)
	}
	if !validStamp(ctx["at"]) {
		return nil, refusal(InvalidTime)
	}
	if op["op"] == "revise" {
		if r := s.revisionContract(op, existing, hypothetical); r != nil {
			return nil, r
		}
	} else {
		for _, r := range batch {
			if body(r)["statement_kind"] == "decision_record" && !s.eligibleReceipt(body(r)["authority_receipt"], env(r)["issuer"], ctx, hypothetical) {
				return nil, refusal(AuthorityReceiptRequired)
			}
		}
	}
	// CAS has priority over duplicate replacement IDs/versions.
	seen := map[string]bool{}
	for _, r := range batch {
		k := refKey(ref(r))
		if existing[k] != nil || seen[k] {
			return nil, refusal(DuplicateRecord)
		}
		seen[k] = true
	}
	if op["op"] != "revise" {
		current := s.currentRecords(arr(s.snapshot["records"]))
		for _, r := range batch {
			if env(r)["kind"] != "assertion" {
				continue
			}
			d := s.domain(r)
			if obj(d["cardinality"])["mode"] != "single" || body(r)["statement_kind"] == "decision_record" {
				continue
			}
			for _, other := range current {
				if env(other)["kind"] == "assertion" && s.sequence(r) == s.sequence(other) {
					return nil, refusal(VersionConflict)
				}
			}
			current = append(current, r)
		}
	}
	all := append(append([]any{}, arr(s.snapshot["records"])...), batch...)
	for _, r := range batch {
		if refusal := s.ruleContract(r, hypothetical, ctx["at"]); refusal != nil {
			return nil, refusal
		}
	}
	if graphCycle(s.supportGraph(all)) {
		return nil, refusal(Cycle)
	}
	limits := obj(s.policy()["limits"])
	if sequenceOverflow || int64(len(all)) > limits["max_records"].(int64) || int64(len(payload)) > limits["max_payload_bytes"].(int64) {
		return nil, refusal(LimitExceeded)
	}
	for _, r := range batch {
		if env(r)["kind"] == "justification" && int64(len(arr(body(r)["premises"]))) > limits["max_fan_in"].(int64) {
			return nil, refusal(LimitExceeded)
		}
	}
	// Derive conservative lineage disclosure over the whole candidate graph.
	s.taint(batch, hypothetical)
	if s.mint == nil {
		return nil, refusal(Unavailable)
	}
	handle, err := s.mint()
	if err != nil || !validHandle(handle) {
		return nil, refusal(Unavailable)
	}
	for _, entry := range arr(s.runtime()["idempotency"]) {
		if obj(obj(entry)["receipt"])["receipt_handle"] == handle {
			return nil, refusal(Unavailable)
		}
	}
	refs := make([]any, 0, len(batch))
	for _, r := range batch {
		refs = append(refs, ref(r))
	}
	sortRefs(refs)
	outcome := "admitted"
	if op["op"] == "revise" {
		outcome = "revised"
		if relation == "challenge" {
			outcome = "challenged"
		}
	}
	receipt := map[string]any{"type": "receipt", "operation": op["op"], "outcome": outcome, "receipt_handle": handle, "refs": refs, "custody": []any{}, "erasure_status": nil}
	// Commit once. Everything above operates only on detached candidate records.
	next := copyJSON(s.snapshot).(map[string]any)
	next["records"] = all
	runtime := obj(next["runtime"])
	runtime["memory_cut"] = cut + int64(len(batch))
	runtime["committed_cuts"] = set(append(arr(runtime["committed_cuts"]), runtime["memory_cut"]))
	runtime["idempotency"] = append(arr(runtime["idempotency"]), map[string]any{"actor": ctx["actor"], "space": space, "key": op["idempotency_key"], "canonical_request": canonical, "receipt": copyJSON(receipt)})
	if op["op"] == "revise" {
		s.markDirty(runtime, op["revision"], arr(s.snapshot["records"]))
	}
	s.snapshot = next
	return copyJSON(receipt).(map[string]any), nil
}
func batchProposals(op map[string]any) []any {
	if op["op"] == "revise" {
		a := []any{}
		if op["replacement"] != nil {
			a = append(a, op["replacement"])
		}
		return append(a, op["revision"])
	}
	return arr(op["proposals"])
}
func validHandle(h string) bool {
	if len(h) != 32 {
		return false
	}
	for _, c := range h {
		if !(c >= 'a' && c <= 'f' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

// SeedLoad is a harness stimulus, not a memory capability. It changes only the
// protected work seed and never advances a semantic record sequence.
func (s *State) SeedLoad(actor string, work int64) (map[string]any, *Refusal) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if work < 0 {
		return nil, refusal(InvalidShape)
	}
	if actor != s.policy()["owner"] {
		return nil, refusal(NotAuthorized)
	}
	if s.mint == nil {
		return nil, refusal(Unavailable)
	}
	h, e := s.mint()
	if e != nil || !validHandle(h) {
		return nil, refusal(Unavailable)
	}
	s.runtime()["hidden_work"] = work
	return map[string]any{"type": "receipt", "operation": "load", "outcome": "proceeded", "receipt_handle": h, "refs": []any{}, "custody": []any{}, "erasure_status": nil}, nil
}
