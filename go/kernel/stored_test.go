package kernel

import "testing"

// TestStoredRecordBoundary proves standalone validation shares admitted domain
// checks and rejects malformed shapes/registries without fabricating intake facts.
func TestStoredRecordBoundary(t *testing.T) {
	snapshot, op := basicWrite(t)
	s := stateForTest(t, snapshot)
	success(t, s, op)
	record := arr(s.Snapshot()["records"])[0]
	domains := arr(snapshot["domain_schemas"])
	schemas := packageSchemas(t)
	if r := schemas.ValidateStoredRecord(record, domains); r != nil {
		t.Fatal(r)
	}
	for _, tc := range []struct {
		name   string
		mutate func(any)
		want   RefusalCode
	}{
		{"unknown field", func(v any) { obj(v)["extra"] = true }, InvalidShape},
		{"domain value", func(v any) { obj(arr(body(v)["content"])[0])["value"] = int64(2) }, InvalidDomainValue},
		{"slot", func(v any) { body(v)["slot"] = "[1]" }, InvalidDomainValue},
		{"schema version", func(v any) { obj(env(v)["schema"])["version"] = int64(999) }, UnknownSchema},
		{"zero version", func(v any) { env(v)["version"] = int64(0) }, InvalidDomainValue},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := copyJSON(record)
			tc.mutate(v)
			r := schemas.ValidateStoredRecord(v, domains)
			if r == nil || r.Code != tc.want {
				t.Fatal(r)
			}
		})
	}
	for _, v := range []any{nil, []any{}, "record", map[string]any{}, map[string]any{"envelope": nil}} {
		if r := schemas.ValidateStoredRecord(v, domains); r == nil || r.Code != InvalidShape {
			t.Fatal(r)
		}
	}
	var absent *Schemas
	if r := absent.ValidateStoredRecord(record, domains); r == nil || r.Code != InvalidShape {
		t.Fatal(r)
	}
	duplicate := append(append([]any{}, domains...), domains[0])
	if r := schemas.ValidateStoredRecord(record, duplicate); r == nil || r.Code != InvalidDomainValue {
		t.Fatal(r)
	}
	invalid := copyJSON(domains).([]any)
	obj(invalid[0])["extra"] = true
	if r := schemas.ValidateStoredRecord(record, invalid); r == nil || r.Code != InvalidShape {
		t.Fatal(r)
	}
}
