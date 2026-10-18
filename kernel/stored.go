package kernel

// ValidateStoredRecord checks a complete stored record's closed kernel shape,
// positive versions and assertion domain content against an explicit registry.
// It does not grant authority or replace batch admission, references or CAS.
func (s *Schemas) ValidateStoredRecord(record any, domains []any) *Refusal {
	if _, r := CanonicalJSON(record); r != nil {
		return r
	}
	kind, _ := env(record)["kind"].(string)
	if r := s.Validate(record, packageSchema+kind); r != nil {
		return r
	}
	if badVersion(record) {
		return refusal(InvalidDomainValue)
	}
	known := []SchemaRef{}
	for _, d := range domains {
		if r := s.Validate(d, packageSchema+"domain-schema"); r != nil {
			return r
		}
		known = append(known, SchemaRef{ID: obj(d)["id"].(string), Version: obj(d)["version"].(int64)})
	}
	if r := validateDomainDocuments(domains); r != nil {
		return r
	}
	if r := s.ValidateRecord(record, packageSchema+kind, known); r != nil {
		return r
	}
	if kind == "assertion" {
		var domain map[string]any
		for _, d := range domains {
			if equalJSON(env(record)["schema"], map[string]any{"id": obj(d)["id"], "version": obj(d)["version"]}) {
				domain = obj(d)
			}
		}
		var result *Refusal
		assertionContent(record, domain, func(_ string, code RefusalCode) { result = refusal(code) })
		return result
	}
	return nil
}
