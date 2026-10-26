package kernel

import (
	"testing"
	"testing/fstest"
)

// JSON Schema cardinality accepts both inclusive bounds, rejects their nearest
// neighbors and malformed bound declarations, including schemas without items.
func TestArrayCardinality(t *testing.T) {
	for _, schema := range []string{`{"type":"array","items":{"type":"string"},"minItems":1,"maxItems":8}`, `{"type":"array","minItems":1,"maxItems":8}`} {
		s := testSchemas(t, schema)
		for _, n := range []int{0, 1, 8, 9} {
			v := make([]any, n)
			for i := range v {
				v[i] = "value"
			}
			r := s.Validate(v, testSchemaID)
			if (r == nil) != (n >= 1 && n <= 8) {
				t.Fatal(n, r)
			}
		}
	}
	for _, schema := range []string{`{"type":"array","minItems":-1}`, `{"type":"array","maxItems":true}`, `{"type":"array","minItems":2,"maxItems":1}`} {
		if _, r := LoadSchemas(fstest.MapFS{"schema.json": schemaFile(t, testSchemaID, schema)}); r == nil {
			t.Fatal("accepted malformed bounds", schema)
		}
	}
}
