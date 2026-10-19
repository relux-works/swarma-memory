package conformance_test

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/relux-works/swarma-memory/go/conformance"
	"github.com/relux-works/swarma-memory/go/kernel"
)

func normalizationFixture(t *testing.T) map[string]any {
	t.Helper()
	data, err := os.ReadFile("../../spec/kernel/vectors/semantic/B01.json")
	if err != nil {
		t.Fatal(err)
	}
	doc, r := kernel.DecodeJSON(data)
	if r != nil {
		t.Fatal(r)
	}
	return doc.(map[string]any)
}
func normalizationSchemas(t *testing.T) *kernel.Schemas {
	t.Helper()
	s, r := kernel.LoadSchemas(os.DirFS("../../spec/kernel/schemas"))
	if r != nil {
		t.Fatal(r)
	}
	return s
}
func loadNormalizationFixture(t *testing.T, doc map[string]any) ([]conformance.Vector, error) {
	t.Helper()
	data, r := kernel.CanonicalJSON(doc)
	if r != nil {
		t.Fatal(r)
	}
	return conformance.Load(fstest.MapFS{"B01.json": {Data: data}}, normalizationSchemas(t))
}

// This independent test oracle discovers actual handle fields in expected, not
// declarations. It never calls the comparator's pointer/clone/oracle helpers.
func normalizationOracle(doc map[string]any) conformance.Report {
	report := doc["expected"].(map[string]any)
	labels := map[string]string{}
	var walk func(any)
	walk = func(value any) {
		switch node := value.(type) {
		case map[string]any:
			for key, x := range node {
				if key == "authorized_snapshot_handle" || key == "receipt_handle" {
					label := x.(string)
					encoded, ok := labels[label]
					if !ok {
						encoded = fmt.Sprintf("%032x", len(labels)+1)
						labels[label] = encoded
					}
					node[key] = encoded
				} else {
					walk(x)
				}
			}
		case []any:
			for _, x := range node {
				walk(x)
			}
		}
	}
	walk(report)
	return conformance.Report(report)
}

// TestNormalizationReviewWitnesses retains both R1 false-pass witnesses. Loading
// either malformed fixture must return the specific harness error and no suite;
// unchanged B01 with generated wire handles passes as the adjacent control.
func TestNormalizationReviewWitnesses(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		edit       func(map[string]any)
	}{
		{"extra refusal code", "fresh_handles: not a handle field \"/operation_results/0/code\"", func(doc map[string]any) {
			n := doc["normalization"].(map[string]any)
			n["fresh_handles"] = append(n["fresh_handles"].([]any), "/operation_results/0/code")
		}},
		{"missing declarations", "fresh_handles: undeclared handle field \"/operation_results/4/authorized_snapshot_handle\"", func(doc map[string]any) {
			n := doc["normalization"].(map[string]any)
			for _, key := range []string{"fresh_handles", "equal_handles", "distinct_handles"} {
				n[key] = []any{}
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := normalizationFixture(t)
			tc.edit(doc)
			vectors, err := loadNormalizationFixture(t, doc)
			if err == nil {
				report := conformance.Report(doc["expected"].(map[string]any))
				if tc.name == "extra refusal code" {
					report = normalizationOracle(doc)
					report["operation_results"].([]any)[0].(map[string]any)["code"] = strings.Repeat("a", 32)
				}
				t.Fatalf("malformed normalization admitted; false-pass witness: %+v", conformance.Compare(vectors[0], report))
			}
			if vectors != nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got suite %v, error %v; want no suite and %s", vectors, err, tc.want)
			}
		})
	}
	t.Run("valid neighbor", func(t *testing.T) {
		doc := normalizationFixture(t)
		vectors, err := loadNormalizationFixture(t, doc)
		if err != nil || len(vectors) != 1 {
			t.Fatal(vectors, err)
		}
		if verdict := conformance.Compare(vectors[0], normalizationOracle(doc)); !verdict.Pass {
			t.Fatal(verdict)
		}
	})
	t.Run("wrong code remains visible", func(t *testing.T) {
		doc := normalizationFixture(t)
		vectors, err := loadNormalizationFixture(t, doc)
		if err != nil {
			t.Fatal(err)
		}
		report := normalizationOracle(doc)
		report["operation_results"].([]any)[0].(map[string]any)["code"] = "invalid_json"
		got := conformance.Compare(vectors[0], report)
		if got.Pass || got.Rule != "equality" || got.Pointer != "/operation_results/0/code" {
			t.Fatal(got)
		}
	})
}

// TestNormalizationCoverage proves every B01 slot (receipt, top-level view and
// nested polarity) is required; symbolic-looking semantic data cannot become a
// slot. Declaration order is a set property, unlike ordered operation results.
func TestNormalizationCoverage(t *testing.T) {
	paths := normalizationFixture(t)["normalization"].(map[string]any)["fresh_handles"].([]any)
	for i, raw := range paths {
		p := raw.(string)
		t.Run("missing"+p, func(t *testing.T) {
			doc := normalizationFixture(t)
			n := doc["normalization"].(map[string]any)
			slots := n["fresh_handles"].([]any)
			n["fresh_handles"] = append(slots[:i:i], slots[i+1:]...)
			vectors, err := loadNormalizationFixture(t, doc)
			want := "fresh_handles: undeclared handle field " + fmt.Sprintf("%q", p)
			if vectors != nil || err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("got %v, %v; want %s", vectors, err, want)
			}
		})
	}
	t.Run("semantic data with symbolic value", func(t *testing.T) {
		doc := normalizationFixture(t)
		doc["expected"].(map[string]any)["result"].(map[string]any)["items"].([]any)[0].(map[string]any)["content"].([]any)[0].(map[string]any)["value"] = "@h999"
		p := "/result/items/0/content/0/value"
		n := doc["normalization"].(map[string]any)
		n["fresh_handles"] = append(n["fresh_handles"].([]any), p)
		vectors, err := loadNormalizationFixture(t, doc)
		if vectors != nil || err == nil || !strings.Contains(err.Error(), "fresh_handles: not a handle field "+fmt.Sprintf("%q", p)) {
			t.Fatal(vectors, err)
		}
	})
	t.Run("reordered declarations", func(t *testing.T) {
		doc := normalizationFixture(t)
		slots := doc["normalization"].(map[string]any)["fresh_handles"].([]any)
		for i, j := 0, len(slots)-1; i < j; i, j = i+1, j-1 {
			slots[i], slots[j] = slots[j], slots[i]
		}
		vectors, err := loadNormalizationFixture(t, doc)
		if err != nil || len(vectors) != 1 {
			t.Fatal(vectors, err)
		}
		if got := conformance.Compare(vectors[0], normalizationOracle(doc)); !got.Pass {
			t.Fatal(got)
		}
	})
}

// TestNormalizationSymbolicLabels proves the full symbolic grammar is required
// at a real handle field. Valid labels have no machine-integer size limit and
// are converted to wire handles by the independent positive-control oracle.
func TestNormalizationSymbolicLabels(t *testing.T) {
	for _, bad := range []string{"", "literal", strings.Repeat("a", 32), "@h", "@h0", "@h01", "@h-1", "@h+1", "@h1x", "@h1\n", "@h١"} {
		t.Run("invalid/"+bad, func(t *testing.T) {
			doc := normalizationFixture(t)
			doc["expected"].(map[string]any)["operation_results"].([]any)[4].(map[string]any)["authorized_snapshot_handle"] = bad
			vectors, err := loadNormalizationFixture(t, doc)
			want := "fresh_handles: expected symbolic handle @h[1-9][0-9]* at \"/operation_results/4/authorized_snapshot_handle\""
			if vectors != nil || err == nil || !strings.Contains(err.Error(), want) {
				t.Fatal(vectors, err)
			}
		})
	}
	for _, label := range []string{"@h987654321", "@h1" + strings.Repeat("0", 128)} {
		t.Run("valid/"+label, func(t *testing.T) {
			doc := normalizationFixture(t)
			expected := doc["expected"].(map[string]any)
			original := expected["operation_results"].([]any)[4].(map[string]any)["authorized_snapshot_handle"]
			var replace func(any)
			replace = func(value any) {
				switch node := value.(type) {
				case map[string]any:
					for key, x := range node {
						if (key == "authorized_snapshot_handle" || key == "receipt_handle") && x == original {
							node[key] = label
						} else {
							replace(x)
						}
					}
				case []any:
					for _, x := range node {
						replace(x)
					}
				}
			}
			replace(expected)
			vectors, err := loadNormalizationFixture(t, doc)
			if err != nil || len(vectors) != 1 {
				t.Fatal(vectors, err)
			}
			if got := conformance.Compare(vectors[0], normalizationOracle(doc)); !got.Pass {
				t.Fatal(got)
			}
		})
	}
}
