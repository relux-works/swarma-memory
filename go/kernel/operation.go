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
	return nil
}
