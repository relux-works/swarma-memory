package kernel

// ValidateWriteOperation checks the closed proposal wire shape without executing
// admission or granting authority. Persistent adapters must still call State.Write.
func (s *Schemas) ValidateWriteOperation(operation map[string]any) *Refusal {
	if _, r := CanonicalJSON(operation); r != nil {
		return r
	}
	if s == nil || s.roots[packageSchema+"vector"] == nil {
		return refusal(InvalidShape)
	}
	if operation["op"] != "admit" && operation["op"] != "revise" {
		return refusal(UnsupportedOperation)
	}
	if !s.roots[packageSchema+"vector"].properties["operations"].items.matches(operation, nil) {
		return refusal(InvalidShape)
	}
	if !revisionAuxiliaryShape(operation) {
		return refusal(InvalidShape)
	}
	return nil
}

// Cross-record auxiliary constraints supplement the closed proposal schema.
// Existing-record uniqueness is checked after replay and CAS in State.Write.
func revisionAuxiliaryShape(op map[string]any) bool {
	aux, present := op["auxiliaries"]
	if !present || op["op"] != "revise" {
		return true
	}
	relation := body(op["revision"])["relation"]
	if relation != "replace" && relation != "correct" || op["replacement"] == nil {
		return false
	}
	records, ok := aux.([]any)
	if !ok || len(records) < 1 || len(records) > 8 {
		return false
	}
	ids := map[any]bool{env(op["replacement"])["id"]: true, env(op["revision"])["id"]: true}
	sources, cited := map[string]bool{}, map[string]bool{}
	for _, r := range records {
		e := env(r)
		if e["version"] != int64(1) || ids[e["id"]] {
			return false
		}
		ids[e["id"]] = true
		switch e["kind"] {
		case "source":
			sources[refKey(ref(r))] = true
		case "justification":
			if !equalJSON(obj(body(r)["target"])["assertion"], ref(op["replacement"])) {
				return false
			}
			for _, p := range arr(body(r)["premises"]) {
				if obj(p)["kind"] == "source" {
					cited[refKey(obj(p)["source"])] = true
				}
			}
		default:
			return false
		}
	}
	for source := range sources {
		if !cited[source] {
			return false
		}
	}
	return true
}
