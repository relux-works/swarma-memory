package space

import (
	"context"
	"sort"
	"strings"
)

func (p *VerifiedPolicy) readable(principal string) bool {
	if p == nil {
		return false
	}
	for _, reader := range p.policy.Readers {
		if reader.Identity == principal || reader.Identity == "public" {
			return true
		}
	}
	return false
}

// Read evaluates a complete recall/explain/changes query through the kernel. The
// latest verified space policy must also authorize the principal to read.
func (r *Repository) Read(query map[string]any) (map[string]any, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.read(query)
}
func (r *Repository) read(query map[string]any) (map[string]any, error) {
	principal, _ := query["principal"].(string)
	if r.state == nil {
		return nil, fail("not_synced")
	}
	if !r.policy.readable(principal) {
		return nil, fail("not_authorized")
	}
	view, f := r.state.Read(query)
	if f != nil {
		return nil, fail(string(f.Code))
	}
	return view, nil
}

// Capture binds a kernel changes baseline in the currently verified state.
// Sync rebuilds history, so persistent changes use ChangesSince instead.
func (r *Repository) Capture(index int64, query map[string]any) (map[string]any, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	principal, _ := query["principal"].(string)
	if r.state == nil {
		return nil, fail("not_synced")
	}
	if !r.policy.readable(principal) {
		return nil, fail("not_authorized")
	}
	view, f := r.state.Capture(index, query)
	if f != nil {
		return nil, fail(string(f.Code))
	}
	return view, nil
}

type SpaceQuery struct {
	Repository *Repository
	Query      map[string]any
}
type SpaceView struct {
	Space       string         `json:"space"`
	Cursor      string         `json:"cursor"`
	View        map[string]any `json:"view"`
	Diagnostics []Diagnostic   `json:"diagnostics"`
}

// ReadSpaces syncs and evaluates every explicitly requested readable space. It
// retains each kernel view's provenance, cuts, bounds and authorization handle;
// a sorted collection is not presented as a new cross-space authority or order.
// On rewritten history it returns the last verified view plus that sync error.
func ReadSpaces(ctx context.Context, queries []SpaceQuery) ([]SpaceView, error) {
	views := []SpaceView{}
	var syncError error
	seen := map[string]bool{}
	for _, entry := range queries {
		if entry.Repository == nil {
			return nil, fail("invalid_request")
		}
		r := entry.Repository
		if e := r.Sync(ctx); e != nil {
			if errorCode(e) != "history_rewritten" {
				return nil, e
			}
			syncError = e
		}
		r.mu.Lock()
		if r.policy == nil {
			r.mu.Unlock()
			return nil, fail("not_synced")
		}
		space := r.policy.policy.SpaceID
		if seen[space] {
			r.mu.Unlock()
			return nil, fail("duplicate_space")
		}
		seen[space] = true
		view, e := r.read(entry.Query)
		if e != nil {
			r.mu.Unlock()
			return nil, e
		}
		views = append(views, SpaceView{space, r.current.Cursor, view, append([]Diagnostic{}, r.current.Diagnostics...)})
		r.mu.Unlock()
	}
	sort.Slice(views, func(i, j int) bool { return views[i].Space < views[j].Space })
	return views, syncError
}

// ChangesSince reconstructs a protected changes capture at an ancestor cursor,
// then replays to the current verified cursor. The query remains complete and
// kernel-authorized; a git commit is never used as an authorization handle.
func (r *Repository) ChangesSince(ctx context.Context, query map[string]any, since string) (map[string]any, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	principal, _ := query["principal"].(string)
	if r.current == nil {
		return nil, fail("not_synced")
	}
	if !r.policy.readable(principal) {
		return nil, fail("not_authorized")
	}
	if refusal := r.config.Schemas.Validate(query, "urn:bounded-evidence:0.2.6:query"); refusal != nil {
		return nil, fail(string(refusal.Code))
	}
	if !objectID(since) {
		return nil, fail("invalid_cursor")
	}
	commits, e := r.git(ctx, nil, "rev-list", "--first-parent", r.current.Cursor)
	if e != nil {
		return nil, e
	}
	found := false
	for _, id := range strings.Fields(string(commits)) {
		if id == since {
			found = true
		}
	}
	if !found {
		return nil, fail("invalid_cursor")
	}
	_, _, state, e := r.replayCapture(ctx, r.current.Cursor, since, query)
	if e != nil {
		return nil, e
	}
	q := detached(query)
	q["kind"] = "changes"
	q["since"] = int64(0)
	view, f := state.Read(q)
	if f != nil {
		return nil, fail(string(f.Code))
	}
	return view, nil
}
