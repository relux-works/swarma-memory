package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/relux-works/swarma-memory/go/agentprofile"
	"github.com/relux-works/swarma-memory/go/kernel"
	"github.com/relux-works/swarma-memory/go/space"
)

func ownDirectory(ctx context.Context, c localConfig, id string) (*space.Repository, error) {
	s, e := selectSpace(c, id)
	if e != nil {
		return nil, e
	}
	r, e := openSpace(ctx, s)
	if e != nil {
		return nil, e
	}
	p := r.VerifiedPolicy()
	if p.Policy().Kind != "platform" {
		return nil, cliError{"directory_not_platform", 3}
	}
	if space.IdentityNamespace(c.Identity) != p.OwnerNamespace() {
		return nil, cliError{"identity_owner_mismatch", 3}
	}
	return r, nil
}

func directoryCLI(ctx context.Context, h home, c localConfig, a arguments) (any, error) {
	if len(a.pos) != 2 {
		return nil, cliError{"usage", 2}
	}
	action := a.pos[1]
	switch action {
	case "advertise":
		if e := a.allow("space", "out", "bindings"); e != nil {
			return nil, e
		}
		id, e := a.required("space")
		if e != nil {
			return nil, e
		}
		out, e := a.required("out")
		if e != nil {
			return nil, e
		}
		s, e := selectSpace(c, id)
		if e != nil {
			return nil, e
		}
		r, e := openSpace(ctx, s)
		if e != nil {
			return nil, e
		}
		k, e := h.key(c)
		if e != nil {
			return nil, e
		}
		bindings := []space.Binding{}
		if s.Kind == "project" {
			bindings = append(bindings, space.Binding{Kind: "project", ID: s.ID})
		}
		if file, ok := a.flags["bindings"]; ok {
			b, e := readInputFile(file)
			if e != nil {
				return nil, e
			}
			// Reuse the closed adapter schema through the canonical advertisement check;
			// first reject unknown/duplicate fields using the strict JSON boundary.
			v, f := kernel.DecodeJSON(b)
			if f != nil {
				return nil, f
			}
			list, ok := v.([]any)
			if !ok {
				return nil, cliError{"invalid_bindings", 3}
			}
			bindings = []space.Binding{}
			for _, raw := range list {
				m, ok := raw.(map[string]any)
				if !ok || len(m) != 2 {
					return nil, cliError{"invalid_bindings", 3}
				}
				kind, kok := m["kind"].(string)
				id, iok := m["id"].(string)
				if !kok || !iok {
					return nil, cliError{"invalid_bindings", 3}
				}
				bindings = append(bindings, space.Binding{Kind: kind, ID: id})
			}
		}
		ad, e := r.Advertisement(k.Identity(), space.Location{Remote: s.Remote, Branch: s.Branch}, bindings, k)
		if e != nil {
			return nil, e
		}
		b, e := json.Marshal(ad)
		if e != nil {
			return nil, cliError{"internal", 6}
		}
		// Exclusive output never overwrites a key, config, or existing advertisement.
		f, e := os.OpenFile(out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return nil, cliError{"output_io", 6}
		}
		_, e = f.Write(append(b, '\n'))
		ce := f.Close()
		if e != nil || ce != nil {
			_ = os.Remove(out)
			return nil, cliError{"output_io", 6}
		}
		return ad, nil
	case "publish", "withdraw", "list", "show":
		flags := []string{"space"}
		if action == "publish" {
			flags = append(flags, "entry")
		}
		if action == "withdraw" || action == "show" {
			flags = append(flags, "space-id")
		}
		if e := a.allow(flags...); e != nil {
			return nil, e
		}
		id, e := a.required("space")
		if e != nil {
			return nil, e
		}
		r, e := ownDirectory(ctx, c, id)
		if e != nil {
			return nil, e
		}
		if action == "list" || action == "show" {
			principal, e := directoryPrincipal(h, c, r)
			if e != nil {
				return nil, e
			}
			items, e := r.Directory(principal)
			if e != nil {
				return nil, e
			}
			if action == "show" && a.flags["space-id"] != "" {
				target, e := a.required("space-id")
				if e != nil {
					return nil, e
				}
				for _, item := range items {
					if item.Entry.SpaceID == target {
						return map[string]any{"entry": item, "diagnostics": r.Diagnostics()}, nil
					}
				}
				return nil, cliError{"directory_missing", 3}
			}
			return map[string]any{"entries": items, "diagnostics": r.Diagnostics()}, nil
		}
		var ad *space.SignedAdvertisement
		target := a.flags["space-id"]
		if action == "publish" {
			file, e := a.required("entry")
			if e != nil {
				return nil, e
			}
			b, e := readInputFile(file)
			if e != nil {
				return nil, e
			}
			parsed, e := space.ParseAdvertisement(b)
			if e != nil {
				return nil, e
			}
			ad = &parsed
			target = parsed.Advertisement.SpaceID
		} else if target == "" {
			return nil, cliError{"usage", 2}
		}
		k, e := h.key(c)
		if e != nil {
			return nil, e
		}
		head, e := r.PublishDirectory(ctx, k.Identity(), target, ad, k)
		if e != nil {
			return nil, e
		}
		return map[string]any{"commit": head, "space_id": target}, nil
	}
	return nil, cliError{"usage", 2}
}

// directorySpace verifies in a private staging clone. No failed validation can
// publish a config, replace an existing pin, or consume an existing cache cursor.
func directorySpace(ctx context.Context, h home, c *localConfig, a arguments, update bool) (any, error) {
	if len(a.pos) != 3 {
		return nil, cliError{"usage", 2}
	}
	if e := a.allow("from-directory"); e != nil {
		return nil, e
	}
	platform, e := a.required("from-directory")
	if e != nil {
		return nil, e
	}
	id := a.pos[2]
	old, existing := selectSpace(*c, id)
	exists := existing == nil
	if update && !exists {
		return nil, existing
	}
	directory, e := ownDirectory(ctx, *c, platform)
	if e != nil {
		return nil, e
	}
	principal, e := directoryPrincipal(h, *c, directory)
	if e != nil {
		return nil, e
	}
	ad, e := directory.LookupDirectory(principal, id)
	if e != nil {
		return nil, e
	}
	if exists && old.GenesisDigest != ad.Advertisement.GenesisDigest {
		return nil, cliError{"genesis_conflict", 3}
	}
	if exists && !update {
		return nil, cliError{"duplicate_space", 3}
	}
	if e = space.DirectoryRemote(ad.Advertisement.Git.Remote, os.Environ()); e != nil {
		return nil, e
	}
	clone, cache := h.paths(id)
	s := localSpace{ID: id, Remote: ad.Advertisement.Git.Remote, Branch: ad.Advertisement.Git.Branch, ClonePath: clone, CachePath: cache, GenesisDigest: ad.Advertisement.GenesisDigest, Kind: ad.Advertisement.Kind, DirectorySpace: platform}
	next := *c
	next.Spaces = append([]localSpace{}, c.Spaces...)
	if update {
		for i := range next.Spaces {
			if next.Spaces[i].ID == id {
				next.Spaces[i] = s
			}
		}
	} else {
		next.Spaces = append(next.Spaces, s)
	}
	if _, e = h.encodeConfig(next); e != nil {
		return nil, e
	}
	previous := ""
	if exists {
		dirty, e := gitCall(ctx, old.ClonePath, "status", "--porcelain", "--untracked-files=all")
		if e != nil {
			return nil, e
		}
		if len(dirty) != 0 {
			return nil, cliError{"dirty_clone", 3}
		}
		oldRepo, e := localRepository(old)
		if e != nil {
			return nil, e
		}
		previous = oldRepo.Cursor()
	}
	if e = privateDir(h.state); e != nil {
		return nil, e
	}
	stage, e := os.MkdirTemp(h.state, ".directory-*")
	if e != nil {
		return nil, cliError{"config_io", 6}
	}
	defer os.RemoveAll(stage)
	candidate := s
	candidate.ClonePath = filepath.Join(stage, "clone")
	candidate.CachePath = filepath.Join(stage, "cache")
	if e = space.CloneDirectory(ctx, space.Git{Directory: candidate.ClonePath, Environment: os.Environ()}, s.Remote, s.Branch); e != nil {
		return nil, e
	}
	r, e := openSpace(ctx, candidate)
	if e != nil {
		return nil, cliError{"directory_mismatch", 3}
	}
	if e = r.VerifyAdvertisement(ad); e != nil {
		return nil, e
	}
	if previous != "" {
		b, e := gitCall(ctx, candidate.ClonePath, "rev-list", "--first-parent", r.Cursor())
		if e != nil {
			return nil, e
		}
		found := false
		for _, commit := range strings.Fields(string(b)) {
			if commit == previous {
				found = true
				break
			}
		}
		if !found {
			return nil, cliError{"history_rewritten", 4}
		}
	}
	// Rename only task-owned destinations, with rollback until config publication.
	moved := [][2]string{}
	backups := [][2]string{}
	rollback := func() {
		for i := len(moved) - 1; i >= 0; i-- {
			_ = os.Rename(moved[i][1], moved[i][0])
		}
		for i := len(backups) - 1; i >= 0; i-- {
			_ = os.Rename(backups[i][1], backups[i][0])
		}
	}
	for i, pair := range [][2]string{{candidate.ClonePath, clone}, {candidate.CachePath, cache}} {
		if e = privateDir(filepath.Dir(pair[1])); e != nil {
			rollback()
			return nil, e
		}
		if _, err := os.Lstat(pair[1]); err == nil {
			if !update {
				rollback()
				return nil, cliError{"clone_exists", 3}
			}
			backup := filepath.Join(stage, []string{"old-clone", "old-cache"}[i])
			if e = os.Rename(pair[1], backup); e != nil {
				rollback()
				return nil, cliError{"config_io", 6}
			}
			backups = append(backups, [2]string{pair[1], backup})
		} else if !errors.Is(err, os.ErrNotExist) {
			rollback()
			return nil, cliError{"config_io", 6}
		}
		if e = os.Rename(pair[0], pair[1]); e != nil {
			rollback()
			return nil, cliError{"config_io", 6}
		}
		moved = append(moved, pair)
	}
	if e = h.save(next); e != nil {
		rollback()
		return nil, e
	}
	*c = next
	return summary(s, r), nil
}

func localRepository(s localSpace) (*space.Repository, error) {
	template, schemas, e := agentprofile.Load()
	if e != nil {
		return nil, e
	}
	env := os.Environ()
	if s.DirectorySpace != "" {
		env = space.DirectoryEnvironment(env)
	}
	return space.Open(space.Config{Git: space.Git{Directory: s.ClonePath, Environment: env}, Branch: s.Branch, CacheDirectory: s.CachePath, GenesisDigest: s.GenesisDigest, Template: template, Schemas: schemas, Mint: agentprofile.Mint, Profile: agentprofile.Configure})
}

func directoryPrincipal(h home, c localConfig, r *space.Repository) (string, error) {
	k, e := h.key(c)
	if e != nil {
		return "", e
	}
	principal, ok := readPrincipal(r.VerifiedPolicy().Policy(), k.Identity(), k.ID())
	if !ok {
		return "", cliError{"not_authorized", 3}
	}
	return principal, nil
}
func directoryDiagnostic(ctx context.Context, h home, c localConfig, s localSpace) string {
	if s.DirectorySpace == "" {
		return ""
	}
	r, e := ownDirectory(ctx, c, s.DirectorySpace)
	if e == nil {
		var principal string
		principal, e = directoryPrincipal(h, c, r)
		if e == nil {
			_, e = r.LookupDirectory(principal, s.ID)
		}
	}
	if e != nil {
		return classify(e).Code
	}
	return ""
}
