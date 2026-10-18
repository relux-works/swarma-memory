package kernel

// boundary receives a detached, closed-schema operation under the state lock.
// Mutation is committed only after complete validation and successful minting.
func (s *State) boundary(op map[string]any) (map[string]any, *Refusal) {
	kind := op["op"].(string)
	if kind == "request_check" {
		return nil, refusal(ExecutionRequired)
	}
	if kind == "deliver" {
		return s.deliver(op)
	}
	if op["actor"] != s.policy()["owner"] && kind != "revoke_declassification" && kind != "control" {
		return nil, refusal(NotAuthorized)
	}
	if kind == "revoke_declassification" {
		d := s.decision(op["decision"])
		if d == nil || d["owner"] != op["actor"] {
			return nil, refusal(NotAuthorized)
		}
	}
	if kind == "control" && !contains(s.policy()["external_effect_owners"], op["actor"]) {
		return nil, refusal(NotAuthorized)
	}
	if kind == "erase" {
		return s.erase(op)
	}
	if !validStamp(op["at"]) {
		return nil, refusal(InvalidTime)
	}
	if badVersion(op) {
		return nil, refusal(InvalidDomainValue)
	}
	next := copyJSON(s.snapshot).(map[string]any)
	runtime := obj(next["runtime"])
	outcome, status := "revoked", any(nil)
	custody := []any{}
	switch kind {
	case "revoke":
		runtime["revocations"] = append(arr(runtime["revocations"]), map[string]any{"principal": op["principal"], "audience": op["audience"], "purpose": op["purpose"], "right": op["right"], "at": op["at"], "owner": op["actor"]})
	case "revoke_declassification":
		runtime["revoked_declassifications"] = set(append(arr(runtime["revoked_declassifications"]), op["decision"]))
	case "restore":
		if op["restore_cut"] != s.backupCut {
			return nil, refusal(InvalidTime)
		}
		// Restore storage presence only. Current records, policy, disposition and
		// generation never roll back to the backup's former authority.
		byID := map[string]any{}
		for _, c := range arr(runtime["custody"]) {
			byID[obj(c)["id"].(string)] = c
		}
		for _, old := range s.backupCustody {
			if c := byID[obj(old)["id"].(string)]; c != nil && obj(old)["present"] == true {
				obj(c)["present"] = true
			}
		}
		obligations := set(append(append(arr(runtime["erased"]), arr(obj(runtime["restore"])["obligations"])...), arr(op["obligations"])...))
		runtime["restore"] = map[string]any{"status": "fenced", "external_witness": op["external_witness"], "obligations": obligations}
		outcome, status = "fenced", "access_closed"
	case "reconcile_restore":
		restore := obj(runtime["restore"])
		obligations := set(append(arr(runtime["erased"]), arr(restore["obligations"])...))
		if restore["status"] != "fenced" || op["external_witness"] != true {
			return nil, refusal(ErasureIncomplete)
		}
		for _, r := range obligations {
			if !contains(op["obligations"], r) {
				return nil, refusal(ErasureIncomplete)
			}
		}
		obligations = set(append(obligations, arr(op["obligations"])...))
		closure := s.erasureClosure(obligations)
		for _, c := range arr(runtime["custody"]) {
			m := obj(c)
			if m["controlled"] != true || !intersects(m["inputs"], closure) {
				continue
			}
			if m["reachable"] != true {
				return nil, refusal(ErasureIncomplete)
			}
			m["present"] = false
			custody = append(custody, m["id"])
		}
		runtime["erased"] = set(append(arr(runtime["erased"]), closure...))
		runtime["fences"] = set(append(arr(runtime["fences"]), closure...))
		runtime["restore"] = map[string]any{"status": "open", "external_witness": true, "obligations": obligations}
		outcome, status = "reconciled", "purged_within_boundary"
	case "control":
		observation := op["action"].(string) + "_proceeded"
		runtime["control_observations"] = append(arr(runtime["control_observations"]), observation)
		outcome = "proceeded"
	default:
		return nil, refusal(UnsupportedOperation)
	}
	h, r := s.nextHandle()
	if r != nil {
		return nil, r
	}
	s.snapshot = next
	return receipt(kind, outcome, h, []any{}, set(custody), status), nil
}

func receipt(operation, outcome, handle string, refs, custody []any, status any) map[string]any {
	return map[string]any{"type": "receipt", "operation": operation, "outcome": outcome, "receipt_handle": handle, "refs": refs, "custody": custody, "erasure_status": status}
}
func intersects(a any, b []any) bool {
	for _, v := range arr(a) {
		if contains(b, v) {
			return true
		}
	}
	return false
}
func (s *State) erasureClosure(targets []any) []any {
	closure := set(append([]any{}, targets...))
	for changed := true; changed; {
		changed = false
		for _, r := range arr(s.snapshot["records"]) {
			if !contains(closure, ref(r)) && intersects(s.fact(r)["inputs"], closure) {
				closure = set(append(closure, ref(r)))
				changed = true
			}
		}
	}
	return closure
}
func (s *State) receiptMetadata(r any, actor any, context map[string]any, at any, index map[string]any) bool {
	if r == nil || !s.disclosureAllows(r, context["audience"], context["purpose"], at, index, map[string]bool{}) {
		return false
	}
	for _, right := range []string{"read", "use"} {
		if !s.grant(actor, env(r)["space"], env(r)["id"], context["audience"], context["purpose"], right, true) {
			return false
		}
	}
	return true
}
func (s *State) erase(op map[string]any) (map[string]any, *Refusal) {
	index := recordIndex(arr(s.snapshot["records"]))
	targets := arr(op["targets"])
	if len(targets) == 0 {
		return nil, refusal(InvalidShape)
	}
	space := env(index[refKey(targets[0])])["space"]
	if !s.hasOperationRight(op["actor"], space, "erase") {
		return nil, refusal(NotAuthorized)
	}
	intent := copyJSON(op).(map[string]any)
	delete(intent, "at")
	delete(intent, "idempotency_key")
	canonical := key(intent)
	for _, raw := range arr(s.runtime()["idempotency"]) {
		entry := obj(raw)
		if entry["actor"] != op["actor"] || entry["space"] != space || entry["key"] != op["idempotency_key"] {
			continue
		}
		if obj(entry["receipt"])["operation"] != "erase" {
			return nil, refusal(IdempotencyConflict)
		}
		stored, r := DecodeJSON([]byte(entry["canonical_request"].(string)))
		if r != nil {
			return nil, refusal(InvalidShape)
		}
		for _, v := range arr(obj(entry["receipt"])["refs"]) {
			if !s.receiptMetadata(index[refKey(v)], op["actor"], obj(obj(stored)["receipt_context"]), op["at"], index) {
				return nil, refusal(NotAuthorized)
			}
		}
		if entry["canonical_request"] != canonical {
			return nil, refusal(IdempotencyConflict)
		}
		return copyJSON(entry["receipt"]).(map[string]any), nil
	}
	if badVersion(op) {
		return nil, refusal(InvalidDomainValue)
	}
	if !validStamp(op["at"]) {
		return nil, refusal(InvalidTime)
	}
	for _, v := range targets {
		r := index[refKey(v)]
		if r == nil {
			return nil, refusal(InvalidReference)
		}
		if !s.hasOperationRight(op["actor"], env(r)["space"], "erase") {
			return nil, refusal(NotAuthorized)
		}
	}
	if s.runtime()["erasure_generation"] == maxJSONInteger {
		return nil, refusal(LimitExceeded)
	}
	closure := s.erasureClosure(targets)
	refs := []any{}
	for _, v := range closure {
		if s.receiptMetadata(index[refKey(v)], op["actor"], obj(op["receipt_context"]), op["at"], index) {
			refs = append(refs, v)
		}
	}
	next := copyJSON(s.snapshot).(map[string]any)
	runtime := obj(next["runtime"])
	runtime["fences"] = set(append(arr(runtime["fences"]), closure...))
	runtime["erased"] = set(append(arr(runtime["erased"]), closure...))
	runtime["erasure_generation"] = runtime["erasure_generation"].(int64) + 1
	custody, complete := []any{}, true
	for _, c := range arr(runtime["custody"]) {
		m := obj(c)
		if m["controlled"] != true || !intersects(m["inputs"], closure) {
			continue
		}
		if contains(op["boundary"], m["id"]) && m["reachable"] == true {
			m["present"] = false
			custody = append(custody, m["id"])
		} else {
			complete = false
		}
	}
	h, r := s.nextHandle()
	if r != nil {
		return nil, r
	}
	outcome, status := "incomplete", "purge_pending"
	if complete {
		outcome, status = "purged", "purged_within_boundary"
	}
	sortRefs(refs)
	out := receipt("erase", outcome, h, refs, set(custody), status)
	runtime["idempotency"] = append(arr(runtime["idempotency"]), map[string]any{"actor": op["actor"], "space": space, "key": op["idempotency_key"], "canonical_request": canonical, "receipt": copyJSON(out)})
	s.snapshot = next
	return copyJSON(out).(map[string]any), nil
}
