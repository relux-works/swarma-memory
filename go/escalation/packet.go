// Package escalation formats authorized conflict observations as inert data.
// It has no filesystem discovery, process, network or board operations.
package escalation

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"sync"

	"github.com/relux-works/swarma-memory/go/kernel"
	"github.com/relux-works/swarma-memory/go/space"
)

const Format = "swarma-memory-escalation/1"

type Ref = kernel.SchemaRef
type Dependent struct {
	Task *string `json:"task"`
	Step *string `json:"step"`
}
type Packet struct {
	Format         string     `json:"format"`
	Classification string     `json:"data_classification"`
	Reporter       string     `json:"reporter"`
	Dependent      Dependent  `json:"dependent"`
	Conflicts      []Conflict `json:"conflicts"`
}
type PolicyRef struct {
	Version int64  `json:"version"`
	Digest  string `json:"digest"`
}
type Item struct {
	Ref         Ref    `json:"ref"`
	Subject     string `json:"subject"`
	Schema      Ref    `json:"schema"`
	Issuer      string `json:"issuer"`
	Currentness string `json:"currentness"`
}
type Evidence struct {
	Support      []Ref `json:"support"`
	Oppose       []Ref `json:"oppose"`
	Incompatible []Ref `json:"incompatible_with"`
}
type Conflict struct {
	Key       string    `json:"conflict_key"`
	Kind      string    `json:"kind"`
	Space     string    `json:"space"`
	Commit    string    `json:"commit"`
	Policy    PolicyRef `json:"policy"`
	Items     []Item    `json:"items"`
	Evidence  Evidence  `json:"evidence"`
	Area      *string   `json:"area"`
	Resolvers []string  `json:"resolvers"`
	Basis     string    `json:"resolver_basis"`
}
type LocatedRef struct {
	Space string `json:"space"`
	Ref   Ref    `json:"ref"`
}

func New(reporter string, task, step *string) Packet {
	return Packet{Format, "data", reporter, Dependent{task, step}, []Conflict{}}
}
func object(v any) map[string]any { m, _ := v.(map[string]any); return m }
func array(v any) []any           { a, _ := v.([]any); return a }
func reference(v any) Ref {
	m := object(v)
	id, _ := m["id"].(string)
	version, _ := m["version"].(int64)
	return Ref{ID: id, Version: version}
}
func refLess(a, b Ref) bool { return a.ID < b.ID || a.ID == b.ID && a.Version < b.Version }
func refs(in []Ref) []Ref {
	out := []Ref{}
	seen := map[Ref]bool{}
	for _, r := range in {
		if r.ID != "" && !seen[r] {
			out = append(out, r)
			seen[r] = true
		}
	}
	sort.Slice(out, func(i, j int) bool { return refLess(out[i], out[j]) })
	return out
}
func canonical(v any) []byte {
	b, _ := json.Marshal(v)
	decoded, _ := kernel.DecodeJSON(b)
	b, _ = kernel.CanonicalJSON(decoded)
	return b
}

// Key intentionally excludes reporter, cursor, policy and time. Reported
// cross-space blocks share the key of the complete sorted set of dependencies.
func Key(kind string, located []LocatedRef) string {
	seen := map[LocatedRef]bool{}
	ordered := []LocatedRef{}
	for _, r := range located {
		if !seen[r] {
			ordered = append(ordered, r)
			seen[r] = true
		}
	}
	sort.Slice(ordered, func(i, j int) bool {
		a, b := ordered[i], ordered[j]
		return a.Space < b.Space || a.Space == b.Space && refLess(a.Ref, b.Ref)
	})
	digest := sha256.Sum256(canonical(map[string]any{"kind": kind, "items": ordered}))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func Kinds(item map[string]any) []string {
	out := []string{}
	if item["currentness"] == "ambiguous_current" {
		out = append(out, "ambiguous_current")
	}
	if object(item["support"])["witness"] == "present" && object(item["oppose"])["witness"] == "present" {
		out = append(out, "evidence_conflict")
	}
	if (item["currentness"] == "current" || item["currentness"] == "last_received") && len(array(item["incompatible_with"])) > 0 {
		out = append(out, "incompatible")
	}
	return out
}

// FromView copies only metadata already authorized by an explain. The snapshot
// lookup classifies disclosed proof-root refs by their target literal; it cannot
// introduce a ref not present in the authorized explanation. No prose is copied.
func FromView(view map[string]any, schema Ref, policy space.Policy, digest, commit string, records []any, reported bool) []Conflict {
	index := map[Ref]map[string]any{}
	for _, raw := range records {
		r := object(raw)
		e := object(r["envelope"])
		index[Ref{ID: e["id"].(string), Version: e["version"].(int64)}] = r
	}
	disclosed := map[Ref]bool{}
	for _, path := range array(object(view["explanation"])["paths"]) {
		for _, r := range array(path) {
			disclosed[reference(r)] = true
		}
	}
	out := []Conflict{}
	for _, raw := range array(view["items"]) {
		item := object(raw)
		ref := reference(item["ref"])
		kinds := Kinds(item)
		if reported {
			kinds = []string{"reported"}
		}
		for _, kind := range kinds {
			route := policy.RouteResolvers(schema, item["subject"].(string))
			conflict := Conflict{Kind: kind, Space: policy.SpaceID, Commit: commit, Policy: PolicyRef{policy.Version, digest}, Items: []Item{{ref, item["subject"].(string), schema, item["issuer"].(string), item["currentness"].(string)}}, Evidence: Evidence{[]Ref{}, []Ref{}, []Ref{}}, Area: route.Area, Resolvers: route.Resolvers, Basis: route.Basis}
			group := []map[string]any{item}
			if kind == "ambiguous_current" {
				group = []map[string]any{}
				for _, candidate := range array(view["items"]) {
					other := object(candidate)
					if other["currentness"] == "ambiguous_current" && other["issuer"] == item["issuer"] && string(canonical(other["perspective"])) == string(canonical(item["perspective"])) && string(canonical(object(index[reference(other["ref"])]["body"])["slot"])) == string(canonical(object(index[ref]["body"])["slot"])) {
						group = append(group, other)
					}
				}
			}
			conflict.Items = []Item{}
			located := []LocatedRef{}
			for _, targetItem := range group {
				targetRef := reference(targetItem["ref"])
				conflict.Items = append(conflict.Items, Item{targetRef, targetItem["subject"].(string), schema, targetItem["issuer"].(string), targetItem["currentness"].(string)})
				located = append(located, LocatedRef{policy.SpaceID, targetRef})
			}
			if kind == "incompatible" {
				for _, other := range array(item["incompatible_with"]) {
					located = append(located, LocatedRef{policy.SpaceID, reference(other)})
				}
			}
			for _, targetItem := range group {
				for r := range disclosed {
					record := index[r]
					e, b := object(record["envelope"]), object(record["body"])
					target := object(b["target"])
					if reference(target["assertion"]) != reference(targetItem["ref"]) || e["kind"] != "assessment" && e["kind"] != "justification" {
						continue
					}
					if target["polarity"] == "support" && object(targetItem["support"])["witness"] == "present" {
						conflict.Evidence.Support = append(conflict.Evidence.Support, r)
					}
					if target["polarity"] == "oppose" && object(targetItem["oppose"])["witness"] == "present" {
						conflict.Evidence.Oppose = append(conflict.Evidence.Oppose, r)
					}
				}
			}
			conflict.Evidence.Support = refs(conflict.Evidence.Support)
			conflict.Evidence.Oppose = refs(conflict.Evidence.Oppose)
			for _, r := range array(item["incompatible_with"]) {
				conflict.Evidence.Incompatible = append(conflict.Evidence.Incompatible, reference(r))
			}
			conflict.Evidence.Incompatible = refs(conflict.Evidence.Incompatible)
			conflict.Key = Key(kind, located)
			out = append(out, conflict)
		}
	}
	return out
}

// Normalize merges reported refs only when their verified space/policy cursor
// and route agree. Distinct routes in the same space retain distinct blocks.
func (p *Packet) Normalize(reported bool) {
	if reported {
		all := []LocatedRef{}
		for _, c := range p.Conflicts {
			for _, i := range c.Items {
				all = append(all, LocatedRef{c.Space, i.Ref})
			}
		}
		key := Key("reported", all)
		merged := []Conflict{}
		for _, c := range p.Conflicts {
			c.Key = key
			found := false
			for n := range merged {
				m := &merged[n]
				if m.Space == c.Space && m.Commit == c.Commit && string(canonical(m.Area)) == string(canonical(c.Area)) && m.Basis == c.Basis && string(canonical(m.Resolvers)) == string(canonical(c.Resolvers)) {
					m.Items = append(m.Items, c.Items...)
					m.Evidence.Support = refs(append(m.Evidence.Support, c.Evidence.Support...))
					m.Evidence.Oppose = refs(append(m.Evidence.Oppose, c.Evidence.Oppose...))
					m.Evidence.Incompatible = refs(append(m.Evidence.Incompatible, c.Evidence.Incompatible...))
					found = true
					break
				}
			}
			if !found {
				merged = append(merged, c)
			}
		}
		p.Conflicts = merged
	}
	if !reported {
		merged := []Conflict{}
		for _, c := range p.Conflicts {
			found := false
			for n := range merged {
				m := &merged[n]
				if m.Space == c.Space && m.Key == c.Key && m.Kind == c.Kind {
					m.Items = append(m.Items, c.Items...)
					m.Evidence.Support = refs(append(m.Evidence.Support, c.Evidence.Support...))
					m.Evidence.Oppose = refs(append(m.Evidence.Oppose, c.Evidence.Oppose...))
					m.Evidence.Incompatible = refs(append(m.Evidence.Incompatible, c.Evidence.Incompatible...))
					found = true
					break
				}
			}
			if !found {
				merged = append(merged, c)
			}
		}
		p.Conflicts = merged
	}
	for n := range p.Conflicts {
		seen := map[Ref]bool{}
		items := []Item{}
		for _, i := range p.Conflicts[n].Items {
			if !seen[i.Ref] {
				items = append(items, i)
				seen[i.Ref] = true
			}
		}
		p.Conflicts[n].Items = items
	}
	for n := range p.Conflicts {
		sort.Slice(p.Conflicts[n].Items, func(i, j int) bool { return refLess(p.Conflicts[n].Items[i].Ref, p.Conflicts[n].Items[j].Ref) })
	}
	sort.Slice(p.Conflicts, func(i, j int) bool {
		a, b := p.Conflicts[i], p.Conflicts[j]
		if a.Space != b.Space {
			return a.Space < b.Space
		}
		if a.Key != b.Key {
			return a.Key < b.Key
		}
		return string(canonical(a)) < string(canonical(b))
	})
	seen := map[string]bool{}
	out := []Conflict{}
	for _, c := range p.Conflicts {
		key := string(canonical(c))
		if !seen[key] {
			out = append(out, c)
			seen[key] = true
		}
	}
	p.Conflicts = out
}

//go:embed escalation.schema.json
var files embed.FS
var once sync.Once
var schemas *kernel.Schemas

func Validate(value any) *kernel.Refusal {
	once.Do(func() { schemas, _ = kernel.LoadSchemas(files) })
	b, e := json.Marshal(value)
	if e != nil {
		return &kernel.Refusal{Code: kernel.InvalidShape}
	}
	v, r := kernel.DecodeJSON(b)
	if r != nil {
		return r
	}
	if r := schemas.Validate(v, "urn:bounded-evidence:escalation:1"); r != nil {
		return r
	}
	var p Packet
	_ = json.Unmarshal(b, &p)
	invalid := func() *kernel.Refusal { return &kernel.Refusal{Code: kernel.InvalidShape} }
	hexValue := func(s string, n int) bool {
		if len(s) != n {
			return false
		}
		for _, c := range s {
			if !strings.ContainsRune("0123456789abcdef", c) {
				return false
			}
		}
		return true
	}
	digest := func(s string) bool {
		return strings.HasPrefix(s, "sha256:") && hexValue(strings.TrimPrefix(s, "sha256:"), 64)
	}
	validRef := func(r Ref) bool { return r.ID != "" && r.Version > 0 }
	if p.Reporter == "" {
		return invalid()
	}
	for _, c := range p.Conflicts {
		if !digest(c.Key) || !digest(c.Policy.Digest) || c.Policy.Version < 1 || !(hexValue(c.Commit, 40) || hexValue(c.Commit, 64)) || c.Space == "" || len(c.Items) == 0 || len(c.Resolvers) == 0 {
			return invalid()
		}
		for n, id := range c.Resolvers {
			if id == "" || n > 0 && c.Resolvers[n-1] >= id {
				return invalid()
			}
		}
		for _, i := range c.Items {
			if !validRef(i.Ref) || !validRef(i.Schema) || i.Subject == "" || i.Issuer == "" {
				return invalid()
			}
		}
		for _, list := range [][]Ref{c.Evidence.Support, c.Evidence.Oppose, c.Evidence.Incompatible} {
			for n, r := range list {
				if !validRef(r) || n > 0 && !refLess(list[n-1], r) {
					return invalid()
				}
			}
		}
	}
	return nil
}
