package conformance

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/relux-works/swarma-memory/go/kernel"
)

// PartVerdict measures one operation or inventory without treating a failed
// final read as evidence against an independently checkable write result.
type PartVerdict struct {
	ID, Kind        string
	Pass            bool
	Pointer, Reason string
}

func admission(kind string) bool {
	return kind == "admit" || kind == "admit_raw" || kind == "revise" || kind == "revise_raw"
}

// CompareParts enforces exact typed shape and declared handle constraints for
// each part. It normalizes only valid declared fresh-handle slots inside that
// part; undeclared fields and handle-group violations remain failures.
func CompareParts(v Vector, actual Report) []PartVerdict {
	got := map[string]any(actual)
	expected := v.document["expected"].(map[string]any)
	_, invalid := kernel.CanonicalJSON(got)
	operations := v.document["operations"].([]any)
	norm := v.document["normalization"].(map[string]any)
	compare := func(id, kind, prefix string) PartVerdict {
		result := PartVerdict{ID: id, Kind: kind, Pointer: prefix}
		fail := func(reason string) PartVerdict { result.Reason = reason; return result }
		if invalid != nil {
			return fail("invalid decoded JSON tree")
		}
		a, ok := lookup(got, prefix)
		w, wok := lookup(expected, prefix)
		if !ok || !wok {
			return fail("missing part")
		}
		// Operate on full detached trees so normalization pointers retain their meaning.
		normalized := clone(got).(map[string]any)
		want := clone(expected).(map[string]any)
		inside := func(p string) bool { return p == prefix || strings.HasPrefix(p, prefix+"/") }
		for _, raw := range norm["fresh_handles"].([]any) {
			p := raw.(string)
			if !inside(p) {
				continue
			}
			value, exists := lookup(got, p)
			if !exists || !handle(value) {
				return fail("invalid fresh handle at " + p)
			}
			replace(normalized, p, freshMarker{})
			replace(want, p, freshMarker{})
		}
		for _, name := range []string{"equal_handles", "distinct_handles"} {
			for _, raw := range norm[name].([]any) {
				group := raw.([]any)
				relevant := false
				for _, p := range group {
					if inside(p.(string)) {
						relevant = true
					}
				}
				if !relevant {
					continue
				}
				// A missing endpoint outside this part belongs to that part's
				// verdict. Available endpoints still enforce cross-part groups.
				values := []any{}
				for _, p := range group {
					value, ok := lookup(got, p.(string))
					if !ok || !handle(value) {
						if inside(p.(string)) {
							return fail(name + ": invalid endpoint")
						}
						continue
					}
					values = append(values, value)
				}
				for i, left := range values {
					for _, right := range values[:i] {
						if same(left, right) != (name == "equal_handles") {
							return fail(name + ": group violated")
						}
					}
				}
			}
		}
		for _, raw := range v.document["forbidden"].([]any) {
			f := raw.(map[string]any)
			if inside(f["path"].(string)) && predicate(got, f) {
				return fail("forbidden predicate")
			}
		}
		a, _ = lookup(normalized, prefix)
		w, _ = lookup(want, prefix)
		if p, bad := difference(w, a, prefix); bad {
			result.Pointer = p
			return fail("typed JSON differs")
		}
		result.Pass = true
		return result
	}
	out := make([]PartVerdict, 0, len(operations)+len(inventories))
	for i, op := range operations {
		p := "/operation_results/" + strconv.Itoa(i)
		part := compare(fmt.Sprintf("%s:%d", v.ID(), i), op.(map[string]any)["op"].(string), p)
		if ops, ok := got["operation_results"].([]any); !ok || len(ops) != len(operations) {
			part.Pass = false
			part.Reason = "expected one result per operation"
		}
		out = append(out, part)
	}
	for _, name := range inventories {
		p := "/postconditions/" + name
		part := compare(v.ID()+":"+name, "inventory", p)
		if inv, ok := lookup(got, p); ok {
			list, ok := inv.([]any)
			if !ok {
				part.Pass = false
				part.Reason = "expected inventory array"
			} else {
				for i := 1; i < len(list); i++ {
					a, _ := kernel.CanonicalJSON(list[i-1])
					b, _ := kernel.CanonicalJSON(list[i])
					if string(a) >= string(b) {
						part.Pass = false
						part.Reason = "inventory must be sorted and duplicate-free"
					}
				}
			}
		}
		out = append(out, part)
	}
	return out
}

// CheckOperationRatchet applies the same strict ratchet contract to admission
// results only. Unknown IDs, indexes, operation types and regressions fail.
func CheckOperationRatchet(verdicts []Verdict, text string) ([]string, error) {
	results := []Verdict{}
	for _, v := range verdicts {
		for _, p := range v.Parts {
			if admission(p.Kind) {
				results = append(results, Verdict{ID: p.ID, Pass: p.Pass})
			}
		}
	}
	return CheckRatchet(results, text)
}

// Agreement counts exact matching parts; exclusions are reported separately and
// never silently removed from these raw corpus denominators.
type Agreement struct{ Matched, Total int }

func CountParts(verdicts []Verdict) map[string]Agreement {
	counts := map[string]Agreement{}
	for _, v := range verdicts {
		for _, p := range v.Parts {
			k := p.Kind
			if k == "inventory" {
				k = strings.TrimPrefix(p.Pointer, "/postconditions/")
				if i := strings.IndexByte(k, '/'); i >= 0 {
					k = k[:i]
				}
			}
			c := counts[k]
			c.Total++
			if p.Pass {
				c.Matched++
			}
			counts[k] = c
		}
	}
	return counts
}
