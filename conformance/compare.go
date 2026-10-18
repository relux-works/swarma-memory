package conformance

import (
	"bytes"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/relux-works/swarma-memory/kernel"
)

// Report is the expected-shaped execution report, using kernel decoded JSON types.
// Keeping the root open here lets the comparator detect extra executor fields.
type Report map[string]any

// A private non-JSON marker cannot collide with an undeclared literal string.
type freshMarker struct{}

// Verdict names the first violated rule or differing JSON Pointer. An empty
// Reason means pass. Pointer is an RFC 6901 pointer (the root is the empty string).
type Verdict struct {
	ID                    string
	Pass                  bool
	Rule, Pointer, Reason string
}

func failure(id, rule, pointer, detail string) Verdict {
	return Verdict{ID: id, Rule: rule, Pointer: pointer, Reason: fmt.Sprintf("%s at %q: %s", rule, pointer, detail)}
}

func escape(s string) string { return strings.ReplaceAll(strings.ReplaceAll(s, "~", "~0"), "/", "~1") }
func tokens(pointer string) ([]string, error) {
	if pointer == "" {
		return nil, nil
	}
	if !strings.HasPrefix(pointer, "/") {
		return nil, fmt.Errorf("invalid JSON Pointer %q", pointer)
	}
	parts := strings.Split(pointer[1:], "/")
	for i, s := range parts {
		for j := 0; j < len(s); j++ {
			if s[j] == '~' {
				if j+1 == len(s) || (s[j+1] != '0' && s[j+1] != '1') {
					return nil, fmt.Errorf("invalid JSON Pointer %q", pointer)
				}
				j++
			}
		}
		parts[i] = strings.ReplaceAll(strings.ReplaceAll(s, "~1", "/"), "~0", "~")
	}
	return parts, nil
}
func index(s string, n int) (int, bool) {
	if s == "" || (len(s) > 1 && s[0] == '0') {
		return 0, false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	i, err := strconv.Atoi(s)
	return i, err == nil && i >= 0 && i < n
}
func lookup(value any, pointer string) (any, bool) {
	parts, err := tokens(pointer)
	if err != nil {
		return nil, false
	}
	for _, part := range parts {
		switch v := value.(type) {
		case map[string]any:
			var ok bool
			value, ok = v[part]
			if !ok {
				return nil, false
			}
		case []any:
			i, ok := index(part, len(v))
			if !ok {
				return nil, false
			}
			value = v[i]
		default:
			return nil, false
		}
	}
	return value, true
}
func replace(value any, pointer string, replacement any) bool {
	parts, err := tokens(pointer)
	if err != nil || len(parts) == 0 {
		return false
	}
	parent := value
	for _, part := range parts[:len(parts)-1] {
		switch v := parent.(type) {
		case map[string]any:
			var ok bool
			parent, ok = v[part]
			if !ok {
				return false
			}
		case []any:
			i, ok := index(part, len(v))
			if !ok {
				return false
			}
			parent = v[i]
		default:
			return false
		}
	}
	last := parts[len(parts)-1]
	switch v := parent.(type) {
	case map[string]any:
		if _, ok := v[last]; !ok {
			return false
		}
		v[last] = replacement
	case []any:
		i, ok := index(last, len(v))
		if !ok {
			return false
		}
		v[i] = replacement
	default:
		return false
	}
	return true
}
func clone(value any) any {
	switch v := value.(type) {
	case map[string]any:
		r := make(map[string]any, len(v))
		for k, x := range v {
			r[k] = clone(x)
		}
		return r
	case []any:
		r := make([]any, len(v))
		for i, x := range v {
			r[i] = clone(x)
		}
		return r
	default:
		return value
	}
}
func same(a, b any) bool { _, ok := difference(a, b, ""); return !ok }

// difference compares decoded types, sorted object keys and ordered arrays.
func difference(want, got any, p string) (string, bool) {
	switch w := want.(type) {
	case map[string]any:
		g, ok := got.(map[string]any)
		if !ok {
			return p, true
		}
		keys := make(map[string]bool)
		for k := range w {
			keys[k] = true
		}
		for k := range g {
			keys[k] = true
		}
		sorted := make([]string, 0, len(keys))
		for k := range keys {
			sorted = append(sorted, k)
		}
		sort.Strings(sorted)
		for _, k := range sorted {
			a, aok := w[k]
			b, bok := g[k]
			q := p + "/" + escape(k)
			if !aok || !bok {
				return q, true
			}
			if d, bad := difference(a, b, q); bad {
				return d, true
			}
		}
	case []any:
		g, ok := got.([]any)
		if !ok {
			return p, true
		}
		for i := 0; i < len(w) && i < len(g); i++ {
			if d, bad := difference(w[i], g[i], p+"/"+strconv.Itoa(i)); bad {
				return d, true
			}
		}
		if len(w) != len(g) {
			n := len(w)
			if len(g) < n {
				n = len(g)
			}
			return p + "/" + strconv.Itoa(n), true
		}
	case freshMarker:
		if _, ok := got.(freshMarker); !ok {
			return p, true
		}
	case nil:
		if got != nil {
			return p, true
		}
	case bool:
		g, ok := got.(bool)
		if !ok || w != g {
			return p, true
		}
	case string:
		g, ok := got.(string)
		if !ok || w != g {
			return p, true
		}
	case int64:
		g, ok := got.(int64)
		if !ok || w != g {
			return p, true
		}
	default:
		return p, true
	}
	return "", false
}
func handle(value any) bool {
	s, ok := value.(string)
	if !ok || len(s) != 32 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func predicate(report any, f map[string]any) bool {
	value, ok := lookup(report, f["path"].(string))
	if !ok {
		return false
	}
	switch f["test"] {
	case "exists":
		return true
	case "equals":
		return same(value, f["value"])
	case "contains":
		if list, ok := value.([]any); ok {
			for _, item := range list {
				if same(item, f["value"]) {
					return true
				}
			}
		}
	case "size_equals":
		if list, ok := value.([]any); ok {
			n, ok := f["value"].(int64)
			return ok && int64(len(list)) == n
		}
	}
	return false
}

var inventories = []string{"record_refs", "erased_refs", "custody_present", "dirty", "control_observations", "external_effects"}

func inventoryError(report map[string]any) (string, string) {
	post, ok := report["postconditions"].(map[string]any)
	if !ok {
		return "/postconditions", "expected object"
	}
	for _, key := range inventories {
		p := "/postconditions/" + key
		list, ok := post[key].([]any)
		if !ok {
			return p, "expected array"
		}
		var previous []byte
		for i, item := range list {
			b, r := kernel.CanonicalJSON(item)
			if r != nil {
				return p + "/" + strconv.Itoa(i), "invalid JSON"
			}
			if i > 0 && bytes.Compare(previous, b) >= 0 {
				return p + "/" + strconv.Itoa(i), "inventory must be sorted and duplicate-free"
			}
			previous = b
		}
	}
	return "", ""
}

// Compare enforces K-VEC-1/2. It never mutates either report. Forbidden
// predicates inspect actual values before any handle normalization occurs.
func Compare(v Vector, actual Report) Verdict {
	id := v.ID()
	got := map[string]any(actual)
	if _, r := kernel.CanonicalJSON(got); r != nil {
		return failure(id, "report", "", "invalid decoded JSON tree")
	}
	ops, ok := got["operation_results"].([]any)
	if !ok || len(ops) != len(v.document["operations"].([]any)) {
		return failure(id, "operation_results", "/operation_results", "expected one result per operation, in order")
	}
	for _, raw := range v.document["forbidden"].([]any) {
		f := raw.(map[string]any)
		if predicate(got, f) {
			return failure(id, "forbidden", f["path"].(string), f["test"].(string)+" predicate is true")
		}
	}
	norm := v.document["normalization"].(map[string]any)
	for _, raw := range norm["fresh_handles"].([]any) {
		p := raw.(string)
		value, ok := lookup(got, p)
		if !ok || !handle(value) {
			return failure(id, "fresh_handles", p, "expected exactly 32 lowercase hex characters")
		}
	}
	for _, name := range []string{"equal_handles", "distinct_handles"} {
		for _, raw := range norm[name].([]any) {
			group := raw.([]any)
			for i := 1; i < len(group); i++ {
				a, _ := lookup(got, group[i].(string))
				for j := 0; j < i; j++ {
					b, _ := lookup(got, group[j].(string))
					equal := same(a, b)
					if name == "equal_handles" && !equal || name == "distinct_handles" && equal {
						return failure(id, name, group[i].(string), "handle group violated")
					}
				}
			}
		}
	}
	if p, detail := inventoryError(got); detail != "" {
		return failure(id, "inventory", p, detail)
	}
	normalized := clone(got).(map[string]any)
	expected := clone(v.document["expected"]).(map[string]any)
	for _, raw := range norm["fresh_handles"].([]any) {
		p := raw.(string)
		replace(normalized, p, freshMarker{})
		replace(expected, p, freshMarker{})
	}
	for _, raw := range norm["equivalent_outputs"].([]any) {
		pair := raw.(map[string]any)
		left, lok := lookup(normalized, pair["left"].(string))
		right, rok := lookup(normalized, pair["right"].(string))
		if !lok || !rok {
			return failure(id, "equivalent_outputs", pair["right"].(string), "missing pair endpoint")
		}
		if p, bad := difference(left, right, ""); bad {
			return failure(id, "equivalent_outputs", pair["right"].(string)+p, "normalized pair differs")
		}
	}
	if p, bad := difference(expected, normalized, ""); bad {
		return failure(id, "equality", p, "typed JSON differs")
	}
	return Verdict{ID: id, Pass: true}
}
