package kernel

import "testing"

// TestDomainValuesAndSlotOrder proves exact field types, required/extra fields,
// canonical string sets and declared slot-field order, with a valid typed control.
func TestDomainValuesAndSlotOrder(t *testing.T) {
	prepare := func() (map[string]any, map[string]any) {
		snapshot, op := basicWrite(t)
		r := firstProposal(op)
		for _, raw := range arr(snapshot["domain_schemas"]) {
			d := obj(raw)
			if d["id"] != obj(env(r)["schema"])["id"] {
				continue
			}
			fields := []any{}
			for _, f := range []struct{ name, kind, equality string }{{"count", "integer", "exact"}, {"enabled", "boolean", "exact"}, {"tags", "string_set", "set"}, {"value", "string", "exact"}} {
				fields = append(fields, map[string]any{"name": f.name, "type": f.kind, "equality": f.equality, "required": true, "disclosure_class": "public"})
			}
			d["fields"] = fields
			d["cardinality"] = map[string]any{"mode": "single", "slot_fields": []any{"value", "count"}}
		}
		body(r)["content"] = []any{map[string]any{"field": "count", "value": int64(2)}, map[string]any{"field": "enabled", "value": true}, map[string]any{"field": "tags", "value": []any{"a", "b"}}, map[string]any{"field": "value", "value": "alpha"}}
		body(r)["slot"] = `["alpha",2]`
		return snapshot, op
	}
	for _, tc := range []struct {
		name   string
		change func(any)
	}{
		{"integer is not bool", func(r any) { obj(arr(body(r)["content"])[0])["value"] = true }},
		{"bool is not integer", func(r any) { obj(arr(body(r)["content"])[1])["value"] = int64(1) }},
		{"set order", func(r any) { obj(arr(body(r)["content"])[2])["value"] = []any{"b", "a"} }},
		{"set duplicate", func(r any) { obj(arr(body(r)["content"])[2])["value"] = []any{"a", "a"} }},
		{"missing required", func(r any) { body(r)["content"] = arr(body(r)["content"])[1:] }},
		{"extra field", func(r any) {
			body(r)["content"] = append(arr(body(r)["content"]), map[string]any{"field": "z-extra", "value": "x"})
		}},
		{"slot order", func(r any) { body(r)["slot"] = `[2,"alpha"]` }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			snapshot, op := prepare()
			success(t, stateForTest(t, snapshot), op)
			s := stateForTest(t, snapshot)
			tc.change(firstProposal(op))
			refusalUnchanged(t, s, op, InvalidDomainValue)
		})
	}
}

// TestIncompatibilityDoesNotCreateEvidence proves two unequal domain candidates
// can be stored together without creating an assessment, rule or contrary record.
func TestIncompatibilityDoesNotCreateEvidence(t *testing.T) {
	snapshot, op := basicWrite(t)
	first := firstProposal(op)
	for _, raw := range arr(snapshot["domain_schemas"]) {
		d := obj(raw)
		if d["id"] == obj(env(first)["schema"])["id"] {
			d["incompatibilities"] = []any{map[string]any{"id": "incompat:value", "field": "value", "relation": "unequal", "statement_kinds": []any{"fact"}, "same": []any{"subject", "space", "perspective", "slot"}, "overlap": "required"}}
		}
	}
	second := copyJSON(first)
	env(second)["id"] = "rec:b"
	obj(arr(body(second)["content"])[0])["value"] = "beta"
	authorizeProposal(snapshot, second)
	op["proposals"] = []any{first, second}
	s := stateForTest(t, snapshot)
	success(t, s, op)
	if len(arr(s.snapshot["records"])) != 2 {
		t.Fatal("extra evidence manufactured")
	}
	for _, r := range arr(s.snapshot["records"]) {
		if env(r)["kind"] != "assertion" {
			t.Fatal("opposition manufactured")
		}
	}
}

// TestTeamIssuerGrant proves a team perspective needs an issuer admission grant
// in addition to the representative's operation and retention grants.
func TestTeamIssuerGrant(t *testing.T) {
	snapshot, op := basicWrite(t)
	first := firstProposal(op)
	env(first)["perspective"] = map[string]any{"kind": "team", "principal": "principal:team"}
	success(t, stateForTest(t, snapshot), op)
	s := stateForTest(t, snapshot)
	for _, g := range arr(s.policy()["grants"]) {
		if obj(g)["principal"] == env(first)["issuer"] {
			obj(g)["rights"] = []any{"read", "retain", "revise"}
		}
	}
	obj(op["context"])["actor"] = "representative"
	for _, g := range arr(s.policy()["grants"]) {
		m := copyJSON(g).(map[string]any)
		m["principal"] = "representative"
		m["rights"] = []any{"admit", "retain"}
		s.policy()["grants"] = append(arr(s.policy()["grants"]), m)
	}
	// Separate representation evidence keeps this witness in the content class.
	delegation := map[string]any{"id": "delegation:team", "version": int64(1)}
	env(first)["representation_ref"] = delegation
	s.policy()["representations"] = []any{map[string]any{"ref": delegation, "issuer": env(first)["issuer"], "submitter": "representative", "space": env(first)["space"], "relations": []any{"admit"}, "valid": true}}
	refusalUnchanged(t, s, op, InvalidDomainValue)
}
