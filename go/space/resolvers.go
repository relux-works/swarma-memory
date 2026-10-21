package space

import (
	"sort"
	"strings"

	"github.com/relux-works/swarma-memory/go/kernel"
	"github.com/relux-works/swarma-memory/go/sign"
)

const PolicyFormatV2 = "swarma-memory-policy/2"

type ResolverMatch struct {
	Schemas  []kernel.SchemaRef `json:"schemas"`
	Subjects []string           `json:"subjects"`
}

type ResolverRoute struct {
	Area      *string  `json:"area"`
	Resolvers []string `json:"resolvers"`
	Basis     string   `json:"resolver_basis"`
}

func resolverQualified(p Policy, id string) bool {
	key, reader, writer := false, false, false
	for _, k := range p.Keys {
		key = key || k.Registration.Identity == id
	}
	for _, r := range p.Readers {
		reader = reader || r.Identity == id
	}
	for _, w := range p.Writers {
		writer = writer || w.Identity == id
	}
	ns := IdentityNamespace(p.Owners[0])
	return key && reader && writer && IdentityNamespace(id) == ns && (!strings.Contains(id, "/") || ns != "")
}

// ResolverWarnings exposes invalid legacy routing declarations without giving
// them any authority or changing the signed policy's historical bytes.
func (p Policy) ResolverWarnings() []string {
	out := []string{}
	for _, r := range p.Resolvers {
		for _, id := range r.Identities {
			if !resolverQualified(p, id) {
				out = append(out, id)
			}
		}
	}
	return sortedTexts(out)
}
func sortedTexts(in []string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, x := range in {
		if !seen[x] {
			out = append(out, x)
			seen[x] = true
		}
	}
	sort.Strings(out)
	return out
}
func schemaLess(a, b kernel.SchemaRef) bool {
	return a.ID < b.ID || a.ID == b.ID && a.Version < b.Version
}
func matches(r Resolver, schema kernel.SchemaRef, subject string) bool {
	if r.Match == nil {
		return true
	}
	schemaOK := len(r.Match.Schemas) == 0
	for _, s := range r.Match.Schemas {
		schemaOK = schemaOK || s == schema
	}
	return schemaOK && (len(r.Match.Subjects) == 0 || has(r.Match.Subjects, subject))
}
func catchAll(r Resolver) bool {
	return r.Match == nil || len(r.Match.Schemas) == 0 && len(r.Match.Subjects) == 0
}
func overlap(a, b ResolverMatch) bool {
	schemas := len(a.Schemas) == 0 || len(b.Schemas) == 0
	for _, x := range a.Schemas {
		for _, y := range b.Schemas {
			schemas = schemas || x == y
		}
	}
	subjects := len(a.Subjects) == 0 || len(b.Subjects) == 0
	for _, x := range a.Subjects {
		subjects = subjects || has(b.Subjects, x)
	}
	return schemas && subjects
}
func validateResolvers(p Policy) error {
	areas := map[string]bool{}
	fallback := false
	accepted := map[kernel.SchemaRef]bool{}
	for _, s := range p.Schemas {
		accepted[s] = true
	}
	for i, r := range p.Resolvers {
		if r.Area == "" || areas[r.Area] || r.Match == nil || !uniqueText(r.Identities, true) || !sort.StringsAreSorted(r.Identities) || !uniqueText(r.Match.Subjects, false) || !sort.StringsAreSorted(r.Match.Subjects) {
			return sign.Fail(sign.InvalidPolicy, "resolvers")
		}
		areas[r.Area] = true
		for j, s := range r.Match.Schemas {
			if !accepted[s] {
				return sign.Fail(sign.SchemaNotAccepted, "resolvers.match.schemas")
			}
			if j > 0 && !schemaLess(r.Match.Schemas[j-1], s) {
				return sign.Fail(sign.InvalidPolicy, "resolvers.match.schemas")
			}
		}
		for _, id := range r.Identities {
			if !resolverQualified(p, id) {
				return fail("resolver_unqualified")
			}
		}
		if catchAll(r) {
			if fallback {
				return fail("resolver_overlap")
			}
			fallback = true
			continue
		}
		for _, other := range p.Resolvers[:i] {
			if !catchAll(other) && overlap(*r.Match, *other.Match) {
				return fail("resolver_overlap")
			}
		}
	}
	return nil
}

// RouteResolvers uses only exact schema/subject matches in the verified policy.
// Legacy free-text areas are a single catch-all; their prose is never parsed.
func (p Policy) RouteResolvers(schema kernel.SchemaRef, subject string) ResolverRoute {
	var fallback *Resolver
	legacy := []string{}
	for _, r := range p.Resolvers {
		if r.Match == nil {
			legacy = append(legacy, r.Identities...)
			continue
		}
		if catchAll(r) {
			r := r
			fallback = &r
			continue
		}
		if matches(r, schema, subject) {
			area := r.Area
			return ResolverRoute{&area, append([]string{}, r.Identities...), "named"}
		}
	}
	if len(legacy) > 0 {
		return ResolverRoute{nil, sortedTexts(legacy), "catch_all"}
	}
	if fallback != nil {
		area := fallback.Area
		return ResolverRoute{&area, append([]string{}, fallback.Identities...), "catch_all"}
	}
	return ResolverRoute{nil, sortedTexts(p.Owners), "default_owners"}
}

// UpgradeResolverPolicy is used only for a newly signed policy transition.
// It never rewrites the payload used to verify an old signature.
func UpgradeResolverPolicy(p *Policy) {
	if p.Format == PolicyFormatV2 {
		return
	}
	ids := []string{}
	for _, r := range p.Resolvers {
		ids = append(ids, r.Identities...)
	}
	p.Format = PolicyFormatV2
	p.Resolvers = []Resolver{}
	if len(ids) > 0 {
		p.Resolvers = append(p.Resolvers, Resolver{Area: "legacy", Match: &ResolverMatch{Schemas: []kernel.SchemaRef{}, Subjects: []string{}}, Identities: sortedTexts(ids)})
	}
}
