package kernel

import (
	"sort"
	"strconv"
	"sync"
)

const packageSchema = "urn:bounded-evidence:0.2.6:"

// State owns an admitted snapshot. Reads and writes serialize validation and
// computation under one lock; callers never receive mutable state aliases.
// The adapter supplies opaque fresh handles; the kernel has no clock or entropy IO.
type State struct {
	mu            sync.Mutex
	snapshot      map[string]any
	schemas       *Schemas
	mint          func() (string, error)
	captures      map[int64]capturedView
	issued        map[string]bool
	backupCut     int64
	backupCustody []any
}

var _ Kernel = (*State)(nil)

// NewState accepts only complete, structurally and referentially valid snapshots.
func NewState(snapshot map[string]any, schemas *Schemas, mint func() (string, error)) (*State, *Refusal) {
	if schemas == nil || schemas.roots[packageSchema+"vector"] == nil {
		return nil, refusal(InvalidShape)
	}
	if _, r := CanonicalJSON(snapshot); r != nil {
		return nil, r
	}
	if profile, ok := obj(snapshot["policy"])["profile"].(string); ok && profile != "documentary" && profile != "protected" && profile != "embedded" {
		return nil, refusal(UnknownProfile)
	}
	node := schemas.roots[packageSchema+"vector"].properties["initial_state"]
	if !node.matches(snapshot, nil) {
		return nil, refusal(InvalidShape)
	}
	s := &State{snapshot: copyJSON(snapshot).(map[string]any), schemas: schemas, mint: mint}
	if r := s.validateSnapshot(); r != nil {
		return nil, r
	}
	s.backupCut = s.runtime()["memory_cut"].(int64)
	s.backupCustody = copyJSON(s.runtime()["custody"]).([]any)
	return s, nil
}

// Snapshot returns a detached complete snapshot, including transaction boundaries
// and the original replay receipts. It is a storage API, not an authorized view.
func (s *State) Snapshot() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	return copyJSON(s.snapshot).(map[string]any)
}

// Admit implements the typed kernel interface using the same transaction path as Write.
func (s *State) Admit(ctx Context, batch []Record) (Receipts, *Refusal) {
	proposals := make([]any, len(batch))
	for i, r := range batch {
		proposals[i] = map[string]any(r)
	}
	out, r := s.Write(map[string]any{"op": "admit", "context": map[string]any{"actor": ctx.Actor, "at": ctx.At, "admission_class": ctx.AdmissionClass, "retention_context": map[string]any{"audience": ctx.RetentionContext.Audience, "purpose": ctx.RetentionContext.Purpose}}, "proposals": proposals, "idempotency_key": ctx.IdempotencyKey, "expected_generation": ctx.ExpectedGeneration})
	return Receipts{Receipt: out}, r
}

func obj(v any) map[string]any  { m, _ := v.(map[string]any); return m }
func arr(v any) []any           { a, _ := v.([]any); return a }
func env(r any) map[string]any  { return obj(obj(r)["envelope"]) }
func body(r any) map[string]any { return obj(obj(r)["body"]) }
func ref(r any) map[string]any {
	e := env(r)
	return map[string]any{"id": e["id"], "version": e["version"]}
}
func key(v any) string { b, _ := CanonicalJSON(v); return string(b) }
func refKey(v any) string {
	m := obj(v)
	return key(map[string]any{"id": m["id"], "version": m["version"]})
}
func copyJSON(v any) any {
	switch x := v.(type) {
	case map[string]any:
		m := make(map[string]any, len(x))
		for k, v := range x {
			m[k] = copyJSON(v)
		}
		return m
	case []any:
		a := make([]any, len(x))
		for i, v := range x {
			a[i] = copyJSON(v)
		}
		return a
	default:
		return v
	}
}
func contains(a any, v any) bool {
	for _, x := range arr(a) {
		if equalJSON(x, v) {
			return true
		}
	}
	return false
}
func set(a []any) []any {
	by := map[string]any{}
	for _, v := range a {
		by[key(v)] = v
	}
	keys := make([]string, 0, len(by))
	for k := range by {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]any, 0, len(keys))
	for _, k := range keys {
		out = append(out, by[k])
	}
	return out
}
func ordered(a any) bool { x := arr(a); return equalJSON(x, set(x)) }
func sortRefs(a []any) {
	sort.Slice(a, func(i, j int) bool {
		x, y := obj(a[i]), obj(a[j])
		if x["id"] != y["id"] {
			return x["id"].(string) < y["id"].(string)
		}
		return x["version"].(int64) < y["version"].(int64)
	})
}
func recordIndex(records []any) map[string]any {
	out := map[string]any{}
	for _, r := range records {
		out[refKey(ref(r))] = r
	}
	return out
}
func (s *State) policy() map[string]any  { return obj(s.snapshot["policy"]) }
func (s *State) runtime() map[string]any { return obj(s.snapshot["runtime"]) }
func (s *State) fact(r any) map[string]any {
	for _, f := range arr(s.policy()["lineage_facts"]) {
		if equalJSON(obj(f)["output"], ref(r)) {
			return obj(f)
		}
	}
	return nil
}
func (s *State) domain(r any) map[string]any {
	for _, d := range arr(s.snapshot["domain_schemas"]) {
		m := obj(d)
		if equalJSON(env(r)["schema"], map[string]any{"id": m["id"], "version": m["version"]}) {
			return m
		}
	}
	return nil
}
func validStamp(v any) bool {
	s, ok := v.(string)
	if !ok || len(s) != 20 || s[4] != '-' || s[7] != '-' || s[10] != 'T' || s[13] != ':' || s[16] != ':' || s[19] != 'Z' {
		return false
	}
	for i, c := range s {
		if i == 4 || i == 7 || i == 10 || i == 13 || i == 16 || i == 19 {
			continue
		}
		if c < '0' || c > '9' {
			return false
		}
	}
	n := func(a, b int) int { v, _ := strconv.Atoi(s[a:b]); return v }
	y, m, d := n(0, 4), n(5, 7), n(8, 10)
	if y < 1 || m < 1 || m > 12 || n(11, 13) > 23 || n(14, 16) > 59 || n(17, 19) > 59 {
		return false
	}
	days := []int{31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}
	if y%4 == 0 && (y%100 != 0 || y%400 == 0) {
		days[1] = 29
	}
	return d >= 1 && d <= days[m-1]
}

// Positive versions are semantic invariants even where the structural package
// deliberately uses an unconstrained integer type for an exact reference.
func badVersion(v any) bool {
	switch x := v.(type) {
	case map[string]any:
		if version, ok := x["version"].(int64); ok && version < 1 {
			return true
		}
		for _, value := range x {
			if badVersion(value) {
				return true
			}
		}
	case []any:
		for _, value := range x {
			if badVersion(value) {
				return true
			}
		}
	}
	return false
}

// nextHandle checks the adapter contract without deriving any output from cuts,
// contents, counters or identifiers. Imported replay handles also remain reserved.
func (s *State) nextHandle() (string, *Refusal) {
	if s.mint == nil {
		return "", refusal(Unavailable)
	}
	h, e := s.mint()
	if e != nil || !validHandle(h) || s.issued[h] {
		return "", refusal(Unavailable)
	}
	for _, v := range arr(s.runtime()["idempotency"]) {
		if obj(obj(v)["receipt"])["receipt_handle"] == h {
			return "", refusal(Unavailable)
		}
	}
	if s.issued == nil {
		s.issued = map[string]bool{}
	}
	s.issued[h] = true
	return h, nil
}

// Fork creates an isolated admission candidate while preserving protected capture
// bindings and issued-handle reservations. A rejected candidate cannot mutate its
// source. The new mint is explicit, as at NewState.
func (s *State) Fork(mint func() (string, error)) (*State, *Refusal) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// The source is already admitted. Rechecking historical admission against a
	// newer policy would incorrectly invalidate records after writer revocation.
	next := &State{snapshot: copyJSON(s.snapshot).(map[string]any), schemas: s.schemas, mint: mint}
	next.captures = make(map[int64]capturedView, len(s.captures))
	for index, c := range s.captures {
		next.captures[index] = capturedView{copyJSON(c.query).(map[string]any), copyJSON(c.view).(map[string]any), copyJSON(c.refs).([]any)}
	}
	next.issued = make(map[string]bool, len(s.issued))
	for handle, used := range s.issued {
		next.issued[handle] = used
	}
	next.backupCut = s.backupCut
	next.backupCustody = copyJSON(s.backupCustody).([]any)
	return next, nil
}

// Configure replaces independently trusted policy/projection configuration.
// It never admits records or accepts configuration from a record. Historical
// admission remains bound to the policy at admission; subsequent operations and
// reads use the new policy. Captures retain their original protected bindings.
func (s *State) Configure(policy map[string]any, projections []any) *Refusal {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := copyJSON(s.snapshot).(map[string]any)
	next["policy"], next["projection_rules"] = copyJSON(policy), copyJSON(projections)
	if _, r := CanonicalJSON(next); r != nil {
		return r
	}
	if !s.schemas.roots[packageSchema+"vector"].properties["initial_state"].matches(next, nil) {
		return refusal(InvalidShape)
	}
	if badVersion(next) {
		return refusal(InvalidDomainValue)
	}
	candidate := &State{snapshot: next, schemas: s.schemas}
	// Historic team/self declarations were admitted under their old grants and
	// bindings. Retain those facts for structural validation only; they are never
	// installed as current authority or made available to subsequent writes.
	validation := copyJSON(next).(map[string]any)
	vp := obj(validation["policy"])
	for _, record := range arr(s.snapshot["records"]) {
		e := env(record)
		if obj(e["perspective"])["kind"] == "team" {
			vp["grants"] = append(arr(vp["grants"]), map[string]any{"principal": e["issuer"], "space": e["space"], "audience": "validation:history", "purpose": "validation:history", "rights": []any{"admit"}, "records": []any{"*"}, "metadata": false})
		}
		if e["admission_class"] == "self_declaration" || body(record)["statement_kind"] == "self_declaration" {
			vp["subject_principals"] = append(arr(vp["subject_principals"]), map[string]any{"subject": e["subject"], "principal": e["issuer"]})
		}
	}
	candidate.snapshot = validation
	if r := candidate.validateSnapshot(); r != nil {
		return r
	}
	s.snapshot = next
	return nil
}
