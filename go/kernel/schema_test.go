package kernel

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"
)

const testSchemaID = "urn:bounded-evidence:test:root"
const packageSchemaBase = "urn:bounded-evidence:0.3.0:"

func schemaFile(t *testing.T, id, schema string) *fstest.MapFile {
	t.Helper()
	var doc map[string]json.RawMessage
	if err := json.Unmarshal([]byte(schema), &doc); err != nil {
		t.Fatal(err)
	}
	encodedID, _ := json.Marshal(id)
	doc["$id"] = encodedID
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return &fstest.MapFile{Data: data}
}

func testSchemas(t *testing.T, schema string) *Schemas {
	t.Helper()
	s, r := LoadSchemas(fstest.MapFS{"schema.json": schemaFile(t, testSchemaID, schema)})
	if r != nil {
		t.Fatalf("load fixture schema: %v", r)
	}
	return s
}

func packageSchemas(t *testing.T) *Schemas {
	t.Helper()
	s, r := LoadSchemas(os.DirFS("../../spec/kernel/schemas"))
	if r != nil {
		t.Fatalf("load package schemas: %v", r)
	}
	return s
}

// TestSchemaViolations proves each required structural/typed constraint refuses its specific counterexample and accepts a valid neighbor.
func TestSchemaViolations(t *testing.T) {
	for _, test := range []struct{ name, schema, bad, good string }{
		{"unknown field", `{"type":"object","properties":{"x":{"type":"integer"}},"required":["x"],"additionalProperties":false}`, `{"x":1,"extra":2}`, `{"x":1}`},
		{"missing field", `{"type":"object","properties":{"x":{"type":"integer"}},"required":["x"],"additionalProperties":false}`, `{}`, `{"x":1}`},
		{"wrong type", `{"type":"integer"}`, `"1"`, `1`},
		{"boolean is not integer", `{"type":"integer"}`, `true`, `1`},
		{"integer is not boolean", `{"type":"boolean"}`, `1`, `true`},
		{"oneOf zero", `{"oneOf":[{"type":"integer"},{"type":"string"}]}`, `false`, `1`},
		{"oneOf two", `{"oneOf":[{"type":"integer"},{"enum":[1,2,"ok"]}]}`, `1`, `"ok"`},
		{"const mismatch", `{"type":"string","const":"expected"}`, `"other"`, `"expected"`},
		{"typed const", `{"const":1}`, `true`, `1`},
		{"typed nested const", `{"const":{"x":[1,null]}}`, `{"x":[true,null]}`, `{"x":[1,null]}`},
		{"const absent versus null", `{"const":{"x":null}}`, `{"y":null}`, `{"x":null}`},
		{"typed enum", `{"enum":[1]}`, `true`, `1`},
		{"typed nested enum", `{"enum":[[1,2]]}`, `[true,2]`, `[1,2]`},
		{"enum array order", `{"enum":[[1,2]]}`, `[2,1]`, `[1,2]`},
		{"array items", `{"type":"array","items":{"type":"integer"}}`, `[1,false]`, `[1,2]`},
		{"nested closed object", `{"type":"array","items":{"type":"object","properties":{"x":{"type":"null"}},"required":["x"],"additionalProperties":false}}`, `[{"x":null,"extra":null}]`, `[{"x":null}]`},
		{"null type", `{"type":"null"}`, `false`, `null`},
		{"object versus array", `{"type":"object","properties":{},"additionalProperties":false}`, `[]`, `{}`},
		{"array versus object", `{"type":"array"}`, `{}`, `[]`},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := testSchemas(t, test.schema)
			requireRefusal(t, s.Validate(mustDecode(t, test.bad), testSchemaID), InvalidShape)
			if r := s.Validate(mustDecode(t, test.good), testSchemaID); r != nil {
				t.Fatalf("valid control refused: %v", r)
			}
		})
	}
}

// TestSchemaLoadRefusals proves malformed, unsupported, open and unresolved schemas cannot publish a partial collection; closed schemas still load.
func TestSchemaLoadRefusals(t *testing.T) {
	for _, test := range []struct{ name, schema string }{
		{"unsupported keyword", `{"type":"string","minLength":1}`},
		{"nested unsupported keyword", `{"type":"array","items":{"type":"string","pattern":"x"}}`},
		{"open object", `{"type":"object","properties":{}}`},
		{"explicit open object", `{"type":"object","properties":{},"additionalProperties":true}`},
		{"properties without object type", `{"properties":{},"additionalProperties":false}`},
		{"undefined required field", `{"type":"object","properties":{},"required":["x"],"additionalProperties":false}`},
		{"remote reference", `{"$ref":"https://example.com/schema"}`},
		{"relative reference", `{"$ref":"schema.json"}`},
		{"unregistered package reference", `{"$ref":"urn:bounded-evidence:test:missing"}`},
		{"missing pointer fragment", `{"$ref":"urn:bounded-evidence:test:root#/missing"}`},
		{"non-pointer fragment", `{"$ref":"urn:bounded-evidence:test:root#anchor"}`},
		{"invalid items schema", `{"type":"array","items":false}`},
		{"unsupported type", `{"type":"number"}`},
		{"type list", `{"type":["integer","string"]}`},
		{"malformed required", `{"required":"x"}`},
		{"non-string required", `{"required":[1]}`},
		{"malformed properties", `{"properties":[]}`},
		{"malformed additionalProperties", `{"additionalProperties":{}}`},
		{"malformed enum", `{"enum":{}}`},
		{"malformed oneOf", `{"oneOf":{}}`},
		{"malformed branch", `{"oneOf":[false]}`},
		{"malformed ref", `{"$ref":1}`},
		{"malformed annotation", `{"$schema":false}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			s, r := LoadSchemas(fstest.MapFS{
				"good.json": schemaFile(t, "urn:bounded-evidence:test:good", `{"type":"integer"}`),
				"bad.json":  schemaFile(t, testSchemaID, test.schema),
			})
			requireRefusal(t, r, InvalidShape)
			if s != nil {
				t.Fatal("load refusal published partial schemas")
			}
			if r := testSchemas(t, `{"type":"object","properties":{},"additionalProperties":false}`).Validate(map[string]any{}, testSchemaID); r != nil {
				t.Fatalf("closed positive control refused: %v", r)
			}
		})
	}
	for _, source := range []fs.FS{
		nil, fstest.MapFS{},
		fstest.MapFS{"schema.json": {Data: []byte(`[]`)}},
		fstest.MapFS{"schema.json": {Data: []byte(`{"type":"integer"}`)}},
		fstest.MapFS{"schema.json": {Data: []byte(`{"$id":"https://example.com/schema"}`)}},
		fstest.MapFS{"schema.json": {Data: []byte(`{"$id":"urn:bounded-evidence:test:root#fragment"}`)}},
		fstest.MapFS{
			"a.json": schemaFile(t, testSchemaID, `{"type":"integer"}`),
			"b.json": schemaFile(t, testSchemaID, `{"type":"string"}`),
		},
	} {
		s, r := LoadSchemas(source)
		requireRefusal(t, r, InvalidShape)
		if s != nil {
			t.Fatal("bad schema source returned a collection")
		}
	}
	s, r := LoadSchemas(fstest.MapFS{"schema.json": {Data: []byte(`{"$id":"urn:bounded-evidence:test:root","const":1.0}`)}})
	requireRefusal(t, r, InvalidJSON)
	if s != nil {
		t.Fatal("invalid JSON schema returned a collection")
	}
}

// TestSchemaReferences proves package-only references, escaped/array pointer fragments and sibling constraints work without remote resolution.
func TestSchemaReferences(t *testing.T) {
	const targetID = "urn:bounded-evidence:test:target"
	for _, test := range []struct{ name, target, reference, extra, good, bad string }{
		{"root", `{"type":"integer"}`, targetID, ``, `1`, `true`},
		{"empty fragment", `{"type":"integer"}`, targetID + "#", ``, `1`, `true`},
		{"escaped pointer", `{"type":"object","properties":{"a/b~c":{"type":"integer"}},"additionalProperties":false}`, targetID + "#/properties/a~1b~0c", ``, `1`, `true`},
		{"array pointer", `{"oneOf":[{"type":"integer"},{"type":"string"}]}`, targetID + "#/oneOf/0", ``, `1`, `true`},
		{"ref siblings are conjunction", `{"type":"integer"}`, targetID, `,"const":4`, `4`, `5`},
	} {
		t.Run(test.name, func(t *testing.T) {
			s, r := LoadSchemas(fstest.MapFS{
				"target.json": schemaFile(t, targetID, test.target),
				"root.json":   schemaFile(t, testSchemaID, fmt.Sprintf(`{"$ref":%q%s}`, test.reference, test.extra)),
			})
			if r != nil {
				t.Fatalf("reference load: %v", r)
			}
			if r := s.Validate(mustDecode(t, test.good), testSchemaID); r != nil {
				t.Fatalf("valid reference control refused: %v", r)
			}
			requireRefusal(t, s.Validate(mustDecode(t, test.bad), testSchemaID), InvalidShape)
			requireRefusal(t, s.Validate(mustDecode(t, test.good), "urn:bounded-evidence:test:absent"), InvalidShape)
		})
	}
}

// TestPackageJSON proves every current package JSON file strictly decodes and round-trips, all 14 schemas load, and every vector has valid structure.
func TestPackageJSON(t *testing.T) {
	s := packageSchemas(t)
	if len(s.roots) != 14 {
		t.Fatalf("loaded %d schemas; want 14", len(s.roots))
	}
	root := os.DirFS("../../spec")
	files, vectors := 0, 0
	err := fs.WalkDir(root, ".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".json") {
			return nil
		}
		files++
		t.Run(path, func(t *testing.T) {
			data, err := fs.ReadFile(root, path)
			if err != nil {
				t.Fatal(err)
			}
			value := mustDecode(t, string(data))
			canonical, r := CanonicalJSON(value)
			if r != nil {
				t.Fatal(r)
			}
			roundTrip := mustDecode(t, string(canonical))
			if !reflect.DeepEqual(value, roundTrip) {
				t.Fatal("canonical round trip changed the tree")
			}
			if strings.HasPrefix(path, "kernel/vectors/") {
				vectors++
				if r := s.Validate(value, packageSchemaBase+"vector"); r != nil {
					t.Fatalf("vector failed structural schema: %v", r)
				}
			}
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if files == 0 || vectors == 0 {
		t.Fatal("package corpus was not exercised")
	}
	t.Logf("%d package JSON files, %d closed schemas, %d vectors", files, len(s.roots), vectors)
}

// TestRecordDomainVersions proves structural failures stay invalid_shape and unknown exact assertion schemas never fall back to known versions.
func TestRecordDomainVersions(t *testing.T) {
	s := packageSchemas(t)
	data, err := os.ReadFile("../../spec/kernel/vectors/semantic/P05.json")
	if err != nil {
		t.Fatal(err)
	}
	vector := mustDecode(t, string(data)).(map[string]any)
	state := vector["initial_state"].(map[string]any)
	var domains []SchemaRef
	for _, doc := range state["domain_schemas"].([]any) {
		d := doc.(map[string]any)
		domains = append(domains, SchemaRef{ID: d["id"].(string), Version: d["version"].(int64)})
	}
	var assertion map[string]any
	for _, record := range state["records"].([]any) {
		r := record.(map[string]any)
		if r["envelope"].(map[string]any)["kind"] == "assertion" {
			assertion = r
			break
		}
	}
	if assertion == nil {
		t.Fatal("no assertion fixture found")
	}
	for _, test := range []struct {
		name   string
		change func(map[string]any)
		code   RefusalCode
	}{
		{"unknown version", func(r map[string]any) {
			r["envelope"].(map[string]any)["schema"].(map[string]any)["version"] = int64(9999)
		}, UnknownSchema},
		{"unknown id", func(r map[string]any) {
			r["envelope"].(map[string]any)["schema"].(map[string]any)["id"] = "schema:missing"
		}, UnknownSchema},
		{"missing version", func(r map[string]any) { delete(r["envelope"].(map[string]any)["schema"].(map[string]any), "version") }, InvalidShape},
		{"wrong version type", func(r map[string]any) { r["envelope"].(map[string]any)["schema"].(map[string]any)["version"] = true }, InvalidShape},
		{"unknown field", func(r map[string]any) { r["extra"] = true }, InvalidShape},
		{"missing assertion schema", func(r map[string]any) { r["envelope"].(map[string]any)["schema"] = nil }, InvalidShape},
	} {
		t.Run(test.name, func(t *testing.T) {
			if r := s.ValidateRecord(assertion, packageSchemaBase+"assertion", domains); r != nil {
				t.Fatalf("known exact version refused: %v", r)
			}
			canonical, _ := CanonicalJSON(assertion)
			copy := mustDecode(t, string(canonical)).(map[string]any)
			test.change(copy)
			requireRefusal(t, s.ValidateRecord(copy, packageSchemaBase+"assertion", domains), test.code)
		})
	}
	requireRefusal(t, s.ValidateRecord(assertion, packageSchemaBase+"assertion", nil), UnknownSchema)
}

// TestVectorSchemaViolations proves real loaded vector constraints reject planted violations and leave both valid and refused input trees unchanged.
func TestVectorSchemaViolations(t *testing.T) {
	s := packageSchemas(t)
	data, err := os.ReadFile("../../spec/kernel/vectors/semantic/S34.json")
	if err != nil {
		t.Fatal(err)
	}
	valid := mustDecode(t, string(data))
	before, _ := json.Marshal(valid)
	for _, test := range []struct {
		name   string
		change func(map[string]any)
	}{
		{"unknown top field", func(v map[string]any) { v["extra"] = true }},
		{"missing query", func(v map[string]any) { delete(v, "query") }},
		{"wrong id type", func(v map[string]any) { v["id"] = true }},
		{"unknown profile", func(v map[string]any) { v["profile"] = "unrecognized" }},
		{"wrong result variant", func(v map[string]any) { v["expected"].(map[string]any)["result"] = map[string]any{} }},
		{"unknown nested field", func(v map[string]any) { v["query"].(map[string]any)["extra"] = true }},
	} {
		t.Run(test.name, func(t *testing.T) {
			if r := s.Validate(valid, packageSchemaBase+"vector"); r != nil {
				t.Fatalf("valid vector refused: %v", r)
			}
			copy := mustDecode(t, string(before)).(map[string]any)
			test.change(copy)
			planted, _ := json.Marshal(copy)
			requireRefusal(t, s.Validate(copy, packageSchemaBase+"vector"), InvalidShape)
			after, _ := json.Marshal(copy)
			if string(planted) != string(after) {
				t.Fatal("validation mutated refused input")
			}
			original, _ := json.Marshal(valid)
			if string(before) != string(original) {
				t.Fatal("validation mutated valid input")
			}
		})
	}
}

// TestRecordKinds proves all five admitted record kinds validate structurally and only assertions need a domain registry entry.
func TestRecordKinds(t *testing.T) {
	s := packageSchemas(t)
	kinds := map[string]bool{}
	root := os.DirFS("../../spec/kernel/vectors")
	err := fs.WalkDir(root, ".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() || !strings.HasSuffix(path, ".json") {
			return err
		}
		data, err := fs.ReadFile(root, path)
		if err != nil {
			return err
		}
		vector := mustDecode(t, string(data)).(map[string]any)
		state := vector["initial_state"].(map[string]any)
		var domains []SchemaRef
		for _, value := range state["domain_schemas"].([]any) {
			doc := value.(map[string]any)
			domains = append(domains, SchemaRef{ID: doc["id"].(string), Version: doc["version"].(int64)})
		}
		for _, record := range state["records"].([]any) {
			kind := record.(map[string]any)["envelope"].(map[string]any)["kind"].(string)
			if r := s.ValidateRecord(record, packageSchemaBase+kind, domains); r != nil {
				t.Fatalf("%s %s record refused: %v", path, kind, r)
			}
			kinds[kind] = true
			if kind != "assertion" {
				if r := s.ValidateRecord(record, packageSchemaBase+kind, nil); r != nil {
					t.Fatalf("%s requires a spurious domain registry: %v", kind, r)
				}
				canonical, _ := CanonicalJSON(record)
				copy := mustDecode(t, string(canonical)).(map[string]any)
				copy["envelope"].(map[string]any)["schema"] = map[string]any{"id": "schema:missing", "version": int64(1)}
				requireRefusal(t, s.ValidateRecord(copy, packageSchemaBase+kind, nil), InvalidShape)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(kinds) != 5 {
		t.Fatalf("record coverage %v; want five kinds", kinds)
	}
}

// TestRecursiveSchemas proves references consuming nested instance data terminate correctly and an unproductive ref loop cannot accept a value.
func TestRecursiveSchemas(t *testing.T) {
	s := testSchemas(t, `{"oneOf":[{"type":"null"},{"type":"object","properties":{"next":{"$ref":"urn:bounded-evidence:test:root"}},"required":["next"],"additionalProperties":false}]}`)
	for _, value := range []string{`null`, `{"next":null}`, `{"next":{"next":null}}`} {
		if r := s.Validate(mustDecode(t, value), testSchemaID); r != nil {
			t.Fatalf("finite recursive value refused: %v", r)
		}
	}
	requireRefusal(t, s.Validate(mustDecode(t, `{"next":true}`), testSchemaID), InvalidShape)
	loop := testSchemas(t, `{"$ref":"urn:bounded-evidence:test:root"}`)
	requireRefusal(t, loop.Validate(nil, testSchemaID), InvalidShape)
}
