package main

import (
	"context"
	"encoding/json"
	"sort"
	"strconv"
	"strings"

	"github.com/relux-works/swarma-memory/go/kernel"
	"github.com/relux-works/swarma-memory/go/space"
)

func resolverCLI(ctx context.Context, h home, c localConfig, a arguments) (any, error) {
	if len(a.pos) != 3 {
		return nil, cliError{"usage", 2}
	}
	action := a.pos[2]
	if action != "set" && action != "remove" && action != "show" {
		return nil, cliError{"usage", 2}
	}
	if e := a.allow("space", "area", "schemas", "subjects", "identities"); e != nil {
		return nil, e
	}
	id, e := a.required("space")
	if e != nil {
		return nil, e
	}
	s, e := selectSpace(c, id)
	if e != nil {
		return nil, e
	}
	k, e := h.key(c)
	if e != nil {
		return nil, e
	}
	r, e := openSpace(ctx, s)
	if e != nil {
		return nil, e
	}
	// Show is owner-only too; routing metadata in read packets remains authorized
	// by the dependency read, rather than by this administrative command.
	owner := false
	for _, id := range r.VerifiedPolicy().Policy().Owners {
		owner = owner || id == k.Identity()
	}
	if !owner {
		return nil, cliError{"unauthorized_owner", 3}
	}
	if action == "show" {
		if len(a.flags) != 1 {
			return nil, cliError{"usage", 2}
		}
		return map[string]any{"resolvers": r.VerifiedPolicy().Policy().Resolvers, "warnings": r.VerifiedPolicy().Policy().ResolverWarnings()}, nil
	}
	area, e := a.required("area")
	if e != nil {
		return nil, e
	}
	entry := space.Resolver{Area: area, Match: &space.ResolverMatch{Schemas: []kernel.SchemaRef{}, Subjects: []string{}}, Identities: []string{}}
	if action == "set" {
		// JSON arrays keep opaque subjects and identities free of separator rules.
		for name, target := range map[string]any{"schemas": &entry.Match.Schemas, "subjects": &entry.Match.Subjects, "identities": &entry.Identities} {
			raw := a.flags[name]
			if raw == "" {
				if name == "identities" {
					return nil, cliError{"usage", 2}
				}
				continue
			}
			value, f := kernel.DecodeJSON([]byte(raw))
			if f != nil {
				return nil, cliError{"usage", 2}
			}
			b, _ := json.Marshal(value)
			if json.Unmarshal(b, target) != nil || string(b) == "null" {
				return nil, cliError{"usage", 2}
			}
			// DecodeJSON refuses duplicate keys; closed reference objects are checked by policy schema.
			if name == "schemas" {
				for _, x := range value.([]any) {
					m, ok := x.(map[string]any)
					if !ok || len(m) != 2 {
						return nil, cliError{"usage", 2}
					}
				}
			}
		}
		sort.Strings(entry.Identities)
		sort.Strings(entry.Match.Subjects)
		sort.Slice(entry.Match.Schemas, func(i, j int) bool {
			x, y := entry.Match.Schemas[i], entry.Match.Schemas[j]
			return x.ID < y.ID || x.ID == y.ID && x.Version < y.Version
		})
	} else if len(a.flags) != 2 {
		return nil, cliError{"usage", 2}
	}
	head, e := r.UpdatePolicy(ctx, k.Identity(), k, func(p *space.Policy) error {
		out := []space.Resolver{}
		found := false
		for _, r := range p.Resolvers {
			if r.Area == area {
				found = true
				continue
			}
			out = append(out, r)
		}
		if action == "set" {
			out = append(out, entry)
		} else if !found {
			return cliError{"record_not_found", 3}
		}
		p.Resolvers = out
		return nil
	})
	if e != nil {
		return nil, e
	}
	return map[string]any{"commit": head, "resolvers": r.VerifiedPolicy().Policy().Resolvers}, nil
}

// parseReportedRef resolves colon separators against configured space IDs and
// the final decimal version; ambiguous spellings are refused, never guessed.
func parseReportedRef(raw string, c localConfig) (dependencyRef, error) {
	at := strings.LastIndexByte(raw, ':')
	if at < 0 {
		return dependencyRef{}, cliError{"usage", 2}
	}
	n, e := strconv.ParseInt(raw[at+1:], 10, 64)
	if e != nil || n < 1 {
		return dependencyRef{}, cliError{"usage", 2}
	}
	var out dependencyRef
	count := 0
	for _, s := range c.Spaces {
		prefix := s.ID + ":"
		if strings.HasPrefix(raw[:at], prefix) && len(raw[:at]) > len(prefix) {
			out = dependencyRef{s.ID, raw[len(prefix):at], n}
			count++
		}
	}
	if count == 0 {
		return out, cliError{"record_not_found", 3}
	}
	if count > 1 {
		return out, cliError{"usage", 2}
	}
	return out, nil
}
