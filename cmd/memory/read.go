package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/relux-works/swarma-memory/agentprofile"
	"github.com/relux-works/swarma-memory/space"
)

func readPrincipal(policy space.Policy, identity, keyID string) (string, bool) {
	registered := false
	for _, k := range policy.Keys {
		if k.Registration.Identity == identity && k.Registration.Key == keyID {
			registered = true
		}
	}
	for _, r := range policy.Readers {
		if r.Identity == identity && registered {
			return identity, true
		}
	}
	for _, r := range policy.Readers {
		if r.Identity == "public" {
			return "public", true
		}
	}
	return "", false
}
func cursorMap(s string, spaces []localSpace) (map[string]string, error) {
	if s == "" {
		return map[string]string{}, nil
	}
	if strings.HasPrefix(s, "memory:1:") {
		b, e := base64.RawURLEncoding.Strict().DecodeString(strings.TrimPrefix(s, "memory:1:"))
		if e != nil {
			return nil, cliError{"invalid_cursor", 3}
		}
		m := map[string]string{}
		if e = json.Unmarshal(b, &m); e != nil || len(m) == 0 {
			return nil, cliError{"invalid_cursor", 3}
		}
		return m, nil
	}
	if len(spaces) != 1 {
		return nil, cliError{"invalid_cursor", 3}
	}
	return map[string]string{spaces[0].ID: s}, nil
}
func encodeCursor(m map[string]string) string {
	b, _ := json.Marshal(m)
	return "memory:1:" + base64.RawURLEncoding.EncodeToString(b)
}

func readCLI(ctx context.Context, h home, c localConfig, a arguments) (any, error) {
	cmd := a.pos[0]
	if e := a.allow("space", "rule", "require-current", "since", "at", "version"); e != nil {
		return nil, e
	}
	if cmd == "changes" && len(a.pos) != 1 || cmd != "changes" && len(a.pos) != 2 {
		return nil, cliError{"usage", 2}
	}
	if cmd != "changes" && a.flags["since"] != "" || cmd != "recall" && a.flags["require-current"] != "" {
		return nil, cliError{"usage", 2}
	}
	version := int64(0)
	if raw, ok := a.flags["version"]; ok {
		if cmd != "explain" {
			return nil, cliError{"usage", 2}
		}
		n, e := strconv.ParseInt(raw, 10, 64)
		if e != nil || n < 1 {
			return nil, cliError{"usage", 2}
		}
		version = n
	}
	if rule := a.flags["rule"]; rule != "" && rule != "issuer_current" {
		return nil, cliError{"unknown_rule", 3}
	}
	spaces, e := selected(c, a.flags["space"])
	if e != nil {
		return nil, e
	}
	since, e := cursorMap(a.flags["since"], spaces)
	if e != nil {
		return nil, e
	}
	k, e := h.key(c)
	if e != nil {
		return nil, e
	}
	now := a.flags["at"]
	if now == "" {
		now = time.Now().UTC().Format("2006-01-02T15:04:05Z")
	}
	if t, e := time.Parse("2006-01-02T15:04:05Z", now); e != nil || t.UTC().Format("2006-01-02T15:04:05Z") != now {
		return nil, cliError{"invalid_time", 3}
	}
	outputs := []any{}
	cursors := map[string]string{}
	readable := 0
	found := false
	requireFailure := false
	var syncError error
	for _, s := range spaces {
		r, e := openSpace(ctx, s)
		if e != nil {
			if e.Error() != "history_rewritten" || r == nil || r.VerifiedPolicy() == nil {
				return nil, e
			}
			syncError = e
		}
		principal, ok := readPrincipal(r.VerifiedPolicy().Policy(), k.Identity(), k.ID())
		if !ok {
			continue
		}
		readable++
		cursors[s.ID] = r.Cursor()
		if cmd == "changes" && a.flags["since"] != "" {
			base, ok := since[s.ID]
			if !ok || len(base) != 40 && len(base) != 64 {
				return nil, cliError{"invalid_cursor", 3}
			}
			for _, c := range base {
				if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
					return nil, cliError{"invalid_cursor", 3}
				}
			}
			b, e := gitCall(ctx, s.ClonePath, "rev-list", "--first-parent", r.Cursor())
			if e != nil {
				return nil, e
			}
			found := false
			for _, id := range strings.Fields(string(b)) {
				if id == base {
					found = true
				}
			}
			if !found {
				return nil, cliError{"invalid_cursor", 3}
			}
		}
		snapshot := r.Snapshot()
		p := agentprofile.Object(snapshot["policy"])
		runtime := agentprofile.Object(snapshot["runtime"])
		type scope struct {
			subject string
			schema  any
			rule    string
		}
		scopes := map[string]scope{}
		for _, raw := range agentprofile.Array(snapshot["records"]) {
			env := agentprofile.Object(agentprofile.Object(raw)["envelope"])
			if env["kind"] != "assertion" {
				continue
			}
			rule := agentprofile.RuleID(env["issuer"].(string), env["perspective"])
			schema := env["schema"]
			key, _ := json.Marshal([]any{env["subject"], schema, rule})
			scopes[string(key)] = scope{env["subject"].(string), schema, rule}
		}
		keys := []string{}
		for k := range scopes {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		views := []any{}
		for _, scope := range keys {
			v := scopes[scope]
			targets := []any{}
			if cmd == "explain" {
				id := a.pos[1]
				for _, raw := range agentprofile.Array(snapshot["records"]) {
					env := agentprofile.Object(agentprofile.Object(raw)["envelope"])
					if env["id"] == id && (version == 0 || env["version"] == version) {
						targets = append(targets, agentprofile.Ref(id, env["version"].(int64)))
					}
				}
				if len(targets) == 0 {
					continue
				}
			}
			audience := "aud:private"
			if principal == "public" {
				audience = "aud:public"
			}
			q := map[string]any{"kind": cmd, "principal": principal, "purpose": "purpose:read", "audience": audience, "scope": map[string]any{"space": s.ID, "subject": v.subject, "schema": v.schema, "targets": targets}, "projection_rule": agentprofile.Ref(v.rule, 1), "evidence_policy": agentprofile.Object(p["evidence"])["ref"], "policy": p["revision"], "cut": map[string]any{"memory": runtime["memory_cut"], "sources": runtime["source_cuts"]}, "valid_at": validAt(cmd, now), "now": now, "mode": "real", "bounds": agentprofile.Object(p["limits"])["read"], "usable_until": nil, "render": "full", "since": nil}
			var view map[string]any
			if cmd == "changes" && a.flags["since"] != "" {
				base, ok := since[s.ID]
				if !ok {
					return nil, cliError{"invalid_cursor", 3}
				}
				view, e = r.ChangesSince(ctx, q, base)
			} else {
				view, e = r.Read(q)
			}
			if e != nil {
				return nil, e
			}
			items := []any{}
			for _, raw := range agentprofile.Array(view["items"]) {
				item := agentprofile.Object(raw)
				if cmd == "recall" && a.pos[1] != "*" {
					b, _ := json.Marshal(item["content"])
					if !strings.Contains(strings.ToLower(string(b)), strings.ToLower(a.pos[1])) {
						continue
					}
				}
				item["data_classification"] = "data"
				item["source"] = map[string]any{"space": s.ID, "cursor": r.Cursor(), "refs": item["source_refs"]}
				for _, polarity := range []string{"support", "oppose"} {
					delete(agentprofile.Object(item[polarity]), "authorized_snapshot_handle")
				}
				if item["currentness"] == "ambiguous_current" || agentprofile.Object(item["support"])["witness"] == "present" && agentprofile.Object(item["oppose"])["witness"] == "present" {
					requireFailure = true
				}
				items = append(items, item)
				found = true
			}
			view["items"] = items
			delete(view, "authorized_snapshot_handle")
			// Empty recall/explain scopes are omitted so hidden records cannot leak
			// their subjects, schema combinations or scope counts through CLI data.
			if len(items) > 0 || cmd == "changes" && agentprofile.Object(view["changes"])["state"] == "changed" {
				views = append(views, view)
			}
		}
		outputs = append(outputs, map[string]any{"id": s.ID, "cursor": r.Cursor(), "views": views, "diagnostics": r.Diagnostics()})
	}
	data := map[string]any{"cursor": encodeCursor(cursors), "spaces": outputs}
	if readable == 0 && len(spaces) > 0 {
		return nil, cliError{"not_authorized", 3}
	}
	if cmd == "explain" && !found {
		return nil, cliError{"record_not_found", 3}
	}
	if syncError != nil {
		return data, syncError
	}
	if a.flags["require-current"] != "" && requireFailure {
		return data, cliError{"currentness_required", 7}
	}
	return data, nil
}

func validAt(command, now string) string {
	if command == "recall" {
		return now
	}
	return "any"
}
