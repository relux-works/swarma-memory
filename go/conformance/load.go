package conformance

import (
	"fmt"
	"io/fs"
	"sort"
	"strings"

	"github.com/relux-works/swarma-memory/go/kernel"
)

const vectorSchema = "urn:bounded-evidence:0.3.0:vector"

// Vector is a schema-validated semantic fixture with checked comparison metadata.
// Its expected report stays private and is never passed to an Executor.
type Vector struct{ document map[string]any }

func (v Vector) ID() string { return v.document["id"].(string) }

// Input contains only the complete snapshot, ordered operations and final query.
// Every execution receives its own copy, so an executor cannot alter the oracle.
type Input struct {
	ID           string
	InitialState map[string]any
	Operations   []any
	Query        map[string]any
}

func (v Vector) Input() Input {
	return Input{v.ID(), clone(v.document["initial_state"]).(map[string]any), clone(v.document["operations"]).([]any), clone(v.document["query"]).(map[string]any)}
}

// Load reads every JSON file recursively, in lexical path order. Errors publish
// no partial suite; empty suites, deployment profiles and duplicate IDs are errors.
func Load(source fs.FS, schemas *kernel.Schemas) ([]Vector, error) {
	if source == nil || schemas == nil {
		return nil, fmt.Errorf("harness: vector FS and schemas are required")
	}
	var vectors []Vector
	ids := map[string]bool{}
	err := fs.WalkDir(source, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".json") {
			return nil
		}
		data, err := fs.ReadFile(source, path)
		if err != nil {
			return err
		}
		value, r := kernel.DecodeJSON(data)
		if r != nil {
			return fmt.Errorf("%s: %s", path, r.Code)
		}
		if r = schemas.Validate(value, vectorSchema); r != nil {
			return fmt.Errorf("%s: %s", path, r.Code)
		}
		doc := value.(map[string]any)
		id := doc["id"].(string)
		if doc["profile"] != "semantic" {
			return fmt.Errorf("%s: deployment vectors are out of scope", path)
		}
		if id == "" || ids[id] {
			return fmt.Errorf("%s: empty or duplicate vector id %q", path, id)
		}
		ids[id] = true
		if err := checkContract(doc); err != nil {
			return fmt.Errorf("%s (%s): %w", path, id, err)
		}
		vectors = append(vectors, Vector{doc})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("harness: %w", err)
	}
	if len(vectors) == 0 {
		return nil, fmt.Errorf("harness: no semantic vectors")
	}
	return vectors, nil
}
func checkContract(doc map[string]any) error {
	expected := doc["expected"].(map[string]any)
	if len(expected["operation_results"].([]any)) != len(doc["operations"].([]any)) {
		return fmt.Errorf("/expected/operation_results: expected one result per operation")
	}
	if p, s := inventoryError(expected); s != "" {
		return fmt.Errorf("/expected%s: %s", p, s)
	}
	norm := doc["normalization"].(map[string]any)
	// Derive the allowed slots from the schema-validated expected report, not
	// from normalization metadata that could otherwise erase semantic fields.
	paths := expectedHandleFields(expected)
	fields := make(map[string]bool, len(paths))
	for _, p := range paths {
		fields[p] = true
	}
	slots := map[string]bool{}
	for _, raw := range norm["fresh_handles"].([]any) {
		p := raw.(string)
		parts, err := tokens(p)
		if err != nil || len(parts) < 2 || (parts[0] != "operation_results" && parts[0] != "result") {
			return fmt.Errorf("fresh_handles: invalid report slot %q", p)
		}
		if !fields[p] {
			return fmt.Errorf("fresh_handles: not a handle field %q", p)
		}
		if slots[p] {
			return fmt.Errorf("fresh_handles: duplicate slot %q", p)
		}
		slots[p] = true
	}
	for _, p := range paths {
		if !slots[p] {
			return fmt.Errorf("fresh_handles: undeclared handle field %q", p)
		}
		value, _ := lookup(expected, p)
		if !symbolicHandle(value) {
			return fmt.Errorf("fresh_handles: expected symbolic handle @h[1-9][0-9]* at %q", p)
		}
	}
	for _, name := range []string{"equal_handles", "distinct_handles"} {
		for _, raw := range norm[name].([]any) {
			group := raw.([]any)
			seen := map[string]bool{}
			if len(group) < 2 {
				return fmt.Errorf("%s: group must contain at least two slots", name)
			}
			for i, raw := range group {
				p := raw.(string)
				if !slots[p] || seen[p] {
					return fmt.Errorf("%s: undeclared or duplicate slot %q", name, p)
				}
				seen[p] = true
				a, _ := lookup(expected, p)
				for j := 0; j < i; j++ {
					b, _ := lookup(expected, group[j].(string))
					if name == "equal_handles" && !same(a, b) || name == "distinct_handles" && same(a, b) {
						return fmt.Errorf("%s: inconsistent expected handles at %q", name, p)
					}
				}
			}
		}
	}
	normalized := clone(expected).(map[string]any)
	for p := range slots {
		replace(normalized, p, freshMarker{})
	}
	for _, raw := range norm["equivalent_outputs"].([]any) {
		for _, k := range []string{"left", "right"} {
			p := raw.(map[string]any)[k].(string)
			x, ok := lookup(expected, p)
			if _, obj := x.(map[string]any); !ok || !obj {
				return fmt.Errorf("equivalent_outputs: missing object %q", p)
			}
		}
	}
	for _, raw := range norm["equivalent_outputs"].([]any) {
		pair := raw.(map[string]any)
		left, _ := lookup(normalized, pair["left"].(string))
		right, _ := lookup(normalized, pair["right"].(string))
		if p, bad := difference(left, right, ""); bad {
			return fmt.Errorf("equivalent_outputs: inconsistent expected objects at %q", pair["right"].(string)+p)
		}
	}
	for _, raw := range doc["forbidden"].([]any) {
		f := raw.(map[string]any)
		if _, err := tokens(f["path"].(string)); err != nil {
			return err
		}
		if f["test"] == "size_equals" {
			n, ok := f["value"].(int64)
			if !ok || n < 0 {
				return fmt.Errorf("forbidden size_equals: expected nonnegative integer")
			}
		}
		if predicate(expected, f) {
			return fmt.Errorf("forbidden: expected violates predicate at %q", f["path"])
		}
	}
	return nil
}

// The only normalized fields in the closed report schemas are snapshot and
// receipt handles. Walk every nested object/array so coverage cannot omit a
// polarity's repeated handle or a receipt inside operation_results.
func expectedHandleFields(report any) []string {
	var paths []string
	var walk func(any, string)
	walk = func(value any, path string) {
		switch node := value.(type) {
		case map[string]any:
			for key, x := range node {
				p := path + "/" + escape(key)
				if key == "authorized_snapshot_handle" || key == "receipt_handle" {
					paths = append(paths, p)
				}
				walk(x, p)
			}
		case []any:
			for i, x := range node {
				walk(x, fmt.Sprintf("%s/%d", path, i))
			}
		}
	}
	walk(report, "")
	sort.Strings(paths)
	return paths
}
func symbolicHandle(value any) bool {
	s, ok := value.(string)
	if !ok || len(s) < 3 || !strings.HasPrefix(s, "@h") || s[2] < '1' || s[2] > '9' {
		return false
	}
	for i := 3; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
