package main

import (
	"context"

	"github.com/relux-works/swarma-memory/go/escalation"
)

type dependencyRef struct {
	Space, ID string
	Version   int64
}

func optionalFlag(a arguments, name string) *string {
	v, ok := a.flags[name]
	if !ok {
		return nil
	}
	return &v
}
func conflictsCLI(ctx context.Context, h home, c localConfig, a arguments) (any, error) {
	if len(a.pos) != 1 {
		return nil, cliError{"usage", 2}
	}
	if e := a.allow("space", "id", "ref", "task", "step", "at"); e != nil {
		return nil, e
	}
	read := a
	read.flags = map[string]string{}
	for k, v := range a.flags {
		if k != "id" && k != "ref" {
			read.flags[k] = v
		}
	}
	read.flags["require-current"] = "true"
	if len(a.refs) > 0 {
		if a.flags["space"] != "" || a.flags["id"] != "" {
			return nil, cliError{"usage", 2}
		}
		refs := []dependencyRef{}
		seen := map[dependencyRef]bool{}
		for _, raw := range a.refs {
			r, e := parseReportedRef(raw, c)
			if e != nil {
				return nil, e
			}
			if !seen[r] {
				refs = append(refs, r)
				seen[r] = true
			}
		}
		read.pos = []string{"explain", ""}
		data, e := readDependencies(ctx, h, c, read, refs)
		if e != nil && classify(e).Exit != 7 {
			code := classify(e).Code
			if code == "not_authorized" || code == "unknown_space" || code == "record_not_found" {
				return nil, cliError{"record_not_found", 3}
			}
			return nil, e
		}
		return data, e
	}
	id, e := a.required("id")
	if e != nil {
		return nil, e
	}
	if a.flags["space"] == "" {
		return nil, cliError{"usage", 2}
	}
	read.pos = []string{"explain", id}
	data, e := readCLI(ctx, h, c, read)
	if e != nil {
		if classify(e).Exit == 7 {
			return data.(map[string]any)["escalation"], e
		}
		code := classify(e).Code
		if code == "not_authorized" || code == "unknown_space" {
			return nil, cliError{"record_not_found", 3}
		}
		// This command emits only packets, never the ordinary explain payload
		// (which may include record prose), even on an anti-rollback error.
		return nil, e
	}
	return escalation.New(c.Identity, optionalFlag(a, "task"), optionalFlag(a, "step")), nil
}
