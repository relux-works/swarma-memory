// Package agentprofile implements the provisional documentary CLI integration.
// Only a verified space policy supplies authority; lineage stays unknown.
package agentprofile

import (
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"io/fs"
	"sort"

	assets "github.com/relux-works/swarma-memory/go/assets"
	"github.com/relux-works/swarma-memory/go/kernel"
	"github.com/relux-works/swarma-memory/go/scan"
	"github.com/relux-works/swarma-memory/go/space"
)

//go:embed empty.json
var empty []byte

func Object(v any) map[string]any { m, _ := v.(map[string]any); return m }
func Array(v any) []any           { a, _ := v.([]any); return a }
func Ref(id string, version int64) map[string]any {
	return map[string]any{"id": id, "version": version}
}
func Mint() (string, error) {
	var b [16]byte
	_, e := rand.Read(b[:])
	return hex.EncodeToString(b[:]), e
}

// Load has no filesystem, environment or network discovery.
func Load() (map[string]any, *kernel.Schemas, error) {
	source, e := fs.Sub(assets.Files, "spec/kernel/schemas")
	if e != nil {
		return nil, nil, e
	}
	schemas, f := kernel.LoadSchemas(source)
	if f != nil {
		return nil, nil, f
	}
	v, f := kernel.DecodeJSON(empty)
	if f != nil {
		return nil, nil, f
	}
	snapshot := Object(v)
	domains := []any{}
	for _, dir := range []string{"spec/domains/decisions", "spec/domains/profiles-synthetic"} {
		entries, e := fs.ReadDir(assets.Files, dir)
		if e != nil {
			return nil, nil, e
		}
		for _, entry := range entries {
			b, e := fs.ReadFile(assets.Files, dir+"/"+entry.Name())
			if e != nil {
				return nil, nil, e
			}
			v, f := kernel.DecodeJSON(b)
			if f != nil {
				return nil, nil, f
			}
			if Object(v)["statement_kind"] != nil {
				domains = append(domains, v)
			}
		}
	}
	sort.Slice(domains, func(i, j int) bool { return Object(domains[i])["id"].(string) < Object(domains[j])["id"].(string) })
	snapshot["domain_schemas"] = domains
	if _, f := kernel.NewState(snapshot, schemas, Mint); f != nil {
		return nil, nil, f
	}
	return snapshot, schemas, nil
}

// RuleID names configuration, not an authorization handle.
func RuleID(issuer string, perspective any) string {
	b, _ := kernel.CanonicalJSON([]any{issuer, perspective})
	d := sha256.Sum256(b)
	return "projection:agent-memory:" + hex.EncodeToString(d[:])
}

// Configure is called only with independently verified in-force space policy.
// Signed proposal declarations do not establish complete lineage, third-party
// representation, authority events, external availability or assessment truth.
func Configure(snapshot map[string]any, verified *space.VerifiedPolicy, operation map[string]any) (map[string]any, []any, error) {
	p := Object(snapshot["policy"])
	policy := verified.Policy()
	p["revision"] = Ref("policy:"+verified.Digest(), policy.Version)
	p["owner"] = policy.Owners[0]
	grants := []any{}
	grant := func(identity string, rights []any) {
		for _, audience := range []string{"aud:private", "aud:public"} {
			grants = append(grants, map[string]any{"principal": identity, "space": policy.SpaceID, "audience": audience, "purpose": "purpose:read", "rights": rights, "records": []any{"*"}, "metadata": true})
		}
	}
	for _, reader := range policy.Readers {
		grant(reader.Identity, []any{"read", "use"})
	}
	for _, writer := range policy.Writers {
		grant(writer.Identity, []any{"admit", "retain", "revise"})
	}
	p["grants"] = grants
	bindings := []any{}
	identities := map[string]bool{}
	for _, k := range policy.Keys {
		identities[k.Registration.Identity] = true
	}
	ids := []string{}
	for id := range identities {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		bindings = append(bindings, map[string]any{"subject": id, "principal": id})
	}
	p["subject_principals"] = bindings
	access := []any{}
	for _, record := range Array(snapshot["records"]) {
		e := Object(Object(record)["envelope"])
		if e["kind"] == "source" {
			access = append(access, map[string]any{"source": Ref(e["id"].(string), e["version"].(int64)), "resolvable": false})
		}
	}
	p["source_access"] = access
	batch := Array(operation["proposals"])
	if operation["op"] == "revise" {
		batch = []any{}
		if operation["replacement"] != nil {
			batch = append(batch, operation["replacement"])
		}
		batch = append(batch, operation["revision"])
	}
	known := map[string]bool{}
	for _, f := range Array(p["lineage_facts"]) {
		b, _ := kernel.CanonicalJSON(Object(f)["output"])
		known[string(b)] = true
	}
	for _, record := range batch {
		env := Object(Object(record)["envelope"])
		ref := Ref(env["id"].(string), env["version"].(int64))
		b, _ := kernel.CanonicalJSON(ref)
		if known[string(b)] {
			continue
		}
		known[string(b)] = true
		p["lineage_facts"] = append(Array(p["lineage_facts"]), map[string]any{"output": ref, "profile": Ref("integration:agent-memory", 1), "kind": "deterministic", "inputs": []any{}, "complete": false})
		result := "allow"
		if len(scan.Scan(record, scan.Limits{MaxCanonicalBytes: int(policy.Limits.MaxRecordBytes), MaxStringBytes: int(policy.Limits.MaxFieldBytes), MaxArrayLength: 10000})) > 0 {
			result = "quarantine"
		}
		p["reviews"] = append(Array(p["reviews"]), map[string]any{"record": ref, "reviewer": "integration:agent-memory", "result": result})
	}
	rules := []any{}
	seen := map[string]bool{}
	addRule := func(issuer string, perspective any) {
		id := RuleID(issuer, perspective)
		if seen[id] {
			return
		}
		seen[id] = true
		rules = append(rules, map[string]any{"id": id, "version": int64(1), "issuer": issuer, "perspective": perspective, "sequence_resolution": "issuer_and_authority", "time_policy": "query_cut", "freshness_policy": "query_override_else_schema", "excluded_refs": []any{}, "family": "issuer_current", "audience": nil, "purpose": nil})
	}
	for _, id := range ids {
		for _, kind := range []string{"own", "observer", "team"} {
			addRule(id, map[string]any{"kind": kind, "principal": id})
		}
	}
	for _, record := range append(Array(snapshot["records"]), batch...) {
		e := Object(Object(record)["envelope"])
		if e["kind"] != "assertion" {
			continue
		}
		addRule(e["issuer"].(string), e["perspective"])
	}
	sort.Slice(rules, func(i, j int) bool { return Object(rules[i])["id"].(string) < Object(rules[j])["id"].(string) })
	return p, rules, nil
}
