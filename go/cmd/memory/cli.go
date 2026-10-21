package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/relux-works/swarma-memory/go/agentprofile"
	"github.com/relux-works/swarma-memory/go/kernel"
	"github.com/relux-works/swarma-memory/go/sign"
	"github.com/relux-works/swarma-memory/go/sign/localkey"
	"github.com/relux-works/swarma-memory/go/space"
)

type cliError struct {
	code string
	exit int
}

func (e cliError) Error() string { return e.code }

type missingWriteToken struct{}

func (missingWriteToken) Error() string { return "usage" }

type wireError struct {
	Code string `json:"code"`
	Exit int    `json:"exit"`
}
type result struct {
	Type           string     `json:"type"`
	Command        string     `json:"command"`
	Classification string     `json:"data_classification"`
	Data           any        `json:"data"`
	Error          *wireError `json:"error"`
}

func classify(e error) wireError {
	var missing missingWriteToken
	if errors.As(e, &missing) {
		return wireError{"usage", 2}
	}
	var c cliError
	if errors.As(e, &c) {
		return wireError{c.code, c.exit}
	}
	var hit *space.ScanError
	if errors.As(e, &hit) {
		return wireError{"scan_refused", 3}
	}
	var k *kernel.Refusal
	if errors.As(e, &k) {
		return wireError{string(k.Code), 3}
	}
	var s *sign.Diagnostic
	if errors.As(e, &s) {
		return wireError{string(s.Code), 3}
	}
	var a *space.Error
	if errors.As(e, &a) {
		exit := 3
		if a.Code == "history_rewritten" {
			exit = 4
		}
		if a.Code == "git_failed" || a.Code == "cache_io" || a.Code == "record_io" || a.Code == "policy_io" {
			exit = 6
		}
		return wireError{a.Code, exit}
	}
	return wireError{"internal", 6}
}
func emit(out, errout io.Writer, jsonMode bool, command string, data any, e error) int {
	r := result{"result", command, "data", data, nil}
	code := 0
	if e != nil {
		w := classify(e)
		r.Type = "error"
		r.Error = &w
		code = w.Exit
		var missing missingWriteToken
		if errors.As(e, &missing) {
			fmt.Fprintln(errout, "memory: usage: --expected-version or --expected-token is required")
		} else {
			fmt.Fprintf(errout, "memory: %s\n", w.Code)
		}
	}
	b, err := json.Marshal(r)
	if err != nil {
		fmt.Fprintln(errout, "memory: internal")
		return 6
	}
	if jsonMode {
		fmt.Fprintf(out, "%s\n", b)
	} else {
		fmt.Fprintf(out, "memory data: %s\n", b)
		renderSourceDetails(out, data)
	}
	return code
}

type arguments struct {
	pos   []string
	flags map[string]string
	refs  []string
	json  bool
	home  string
}

func parse(args []string) (arguments, error) {
	a := arguments{flags: map[string]string{}}
	for _, s := range args {
		if s == "--" {
			break
		}
		if s == "--json" {
			a.json = true
		}
	}
	seenHome := false
	for i := 0; i < len(args); i++ {
		s := args[i]
		if s == "--" {
			a.pos = append(a.pos, args[i+1:]...)
			break
		}
		if s == "--json" {
			a.json = true
			continue
		}
		if s == "--require-current" {
			a.flags["require-current"] = "true"
			continue
		}
		if strings.HasPrefix(s, "--") {
			name := strings.TrimPrefix(s, "--")
			if name == "ref" {
				if i+1 == len(args) || strings.HasPrefix(args[i+1], "--") {
					return a, cliError{"usage", 2}
				}
				i++
				a.refs = append(a.refs, args[i])
				a.flags[name] = "true"
				continue
			}
			if _, ok := a.flags[name]; ok {
				return a, cliError{"usage", 2}
			}
			if i+1 == len(args) || strings.HasPrefix(args[i+1], "--") {
				return a, cliError{"usage", 2}
			}
			i++
			if name == "home" {
				if seenHome {
					return a, cliError{"usage", 2}
				}
				seenHome = true
				a.home = args[i]
			} else {
				a.flags[name] = args[i]
			}
			continue
		}
		a.pos = append(a.pos, s)
	}
	return a, nil
}
func (a arguments) allow(names ...string) error {
	for name := range a.flags {
		found := false
		for _, n := range names {
			if n == name {
				found = true
			}
		}
		if !found {
			return cliError{"usage", 2}
		}
	}
	return nil
}
func (a arguments) required(name string) (string, error) {
	v := a.flags[name]
	if v == "" {
		return "", cliError{"usage", 2}
	}
	return v, nil
}

func runCLI(args []string, out, errout io.Writer) int {
	a, e := parse(args)
	command := ""
	if len(a.pos) > 0 {
		command = a.pos[0]
	}
	if e != nil {
		return emit(out, errout, a.json, command, nil, e)
	}
	if command == "version" {
		if len(a.pos) != 1 || len(a.flags) != 0 {
			return emit(out, errout, a.json, command, nil, cliError{"usage", 2})
		}
		return emit(out, errout, a.json, command, map[string]any{"version": version}, nil)
	}
	if command == "conformance" {
		if len(a.flags) != 0 {
			return emit(out, errout, a.json, command, nil, cliError{"usage", 2})
		}
		if !a.json {
			return runConformance(a.pos[1:], out, errout)
		}
		var b, errbuf bytes.Buffer
		code := runConformance(a.pos[1:], &b, &errbuf)
		var err error
		if code != 0 {
			err = cliError{"conformance_failed", code}
		}
		return emit(out, errout, true, command, map[string]any{"report": strings.Split(strings.TrimSpace(b.String()), "\n")}, err)
	}
	h, e := resolveHome(a.home)
	if e != nil {
		return emit(out, errout, a.json, command, nil, e)
	}
	data, e := executeCLI(context.Background(), h, a)
	return emit(out, errout, a.json, command, data, e)
}

func executeCLI(ctx context.Context, h home, a arguments) (any, error) {
	if len(a.pos) == 0 {
		return nil, cliError{"usage", 2}
	}
	cmd := a.pos[0]
	if cmd == "keys" && len(a.pos) == 2 && a.pos[1] == "init" {
		if e := a.allow("identity"); e != nil {
			return nil, e
		}
		identity, e := a.required("identity")
		if e != nil {
			return nil, e
		}
		if _, e := os.Lstat(h.filename()); !errors.Is(e, os.ErrNotExist) {
			return nil, cliError{"already_configured", 3}
		}
		k, e := localkey.Generate(identity)
		if e != nil {
			return nil, e
		}
		c := localConfig{identity, h.keyfile(), []localSpace{}}
		if _, e := h.encodeConfig(c); e != nil {
			return nil, e
		}
		if e := privateDir(h.config); e != nil {
			return nil, e
		}
		if e = k.Save(h.keyfile()); e != nil {
			return nil, e
		}
		if e = h.save(c); e != nil {
			// Save exclusively created this key; a failed config publication must
			// not strand it and prevent initialization with valid input on retry.
			_ = os.Remove(h.keyfile())
			return nil, e
		}
		return keyData(k), nil
	}
	if cmd != "conflicts" && cmd != "directory" && cmd != "keys" && cmd != "spaces" && cmd != "policy" && cmd != "sync" && cmd != "check" && cmd != "recall" && cmd != "explain" && cmd != "changes" && cmd != "add" && cmd != "revise" && cmd != "assess" && cmd != "promote" {
		return nil, cliError{"usage", 2}
	}
	c, e := h.load()
	if e != nil {
		return nil, e
	}
	switch cmd {
	case "directory":
		return directoryCLI(ctx, h, c, a)
	case "keys":
		if len(a.pos) == 2 && a.pos[1] == "show" {
			if e = a.allow(); e != nil {
				return nil, e
			}
			k, e := h.key(c)
			if e != nil {
				return nil, e
			}
			return keyData(k), nil
		}
		if len(a.pos) == 2 && a.pos[1] == "register" {
			return administer(ctx, h, c, a, "register")
		}
	case "spaces":
		if len(a.pos) < 2 {
			return nil, cliError{"usage", 2}
		}
		switch a.pos[1] {
		case "list":
			if len(a.pos) != 2 {
				return nil, cliError{"usage", 2}
			}
			if e = a.allow(); e != nil {
				return nil, e
			}
			return map[string]any{"spaces": c.Spaces}, nil
		case "update":
			return directorySpace(ctx, h, &c, a, true)
		case "init", "add":
			if a.pos[1] == "add" && a.flags["from-directory"] != "" {
				return directorySpace(ctx, h, &c, a, false)
			}
			return addSpace(ctx, h, &c, a, a.pos[1] == "init")
		case "show":
			if len(a.pos) != 3 {
				return nil, cliError{"usage", 2}
			}
			if e = a.allow(); e != nil {
				return nil, e
			}
			s, e := selectSpace(c, a.pos[2])
			if e != nil {
				return nil, e
			}
			r, e := openSpace(ctx, s)
			if e != nil {
				return nil, e
			}
			return summary(s, r), nil
		}
	case "policy":
		if len(a.pos) >= 2 && a.pos[1] == "resolvers" {
			return resolverCLI(ctx, h, c, a)
		}
		if len(a.pos) == 2 && (a.pos[1] == "grant" || a.pos[1] == "revoke") {
			return administer(ctx, h, c, a, a.pos[1])
		}
	case "sync", "check":
		if len(a.pos) != 1 {
			return nil, cliError{"usage", 2}
		}
		if e = a.allow("space"); e != nil {
			return nil, e
		}
		spaces, e := selected(c, a.flags["space"])
		if e != nil {
			return nil, e
		}
		items := []any{}
		bad := false
		for _, s := range spaces {
			r, e := openSpace(ctx, s)
			if e != nil {
				return map[string]any{"spaces": items}, e
			}
			item := summary(s, r).(map[string]any)
			if warning := directoryDiagnostic(ctx, h, c, s); warning != "" {
				item["directory_diagnostic"] = warning
			}
			items = append(items, item)
			bad = bad || len(r.Diagnostics()) > 0
		}
		if cmd == "check" && bad {
			return map[string]any{"spaces": items}, cliError{"verification_failed", 5}
		}
		return map[string]any{"spaces": items}, nil
	case "add", "revise", "assess", "promote":
		return writeCLI(ctx, h, c, a)
	case "conflicts":
		return conflictsCLI(ctx, h, c, a)
	case "recall", "explain", "changes":
		return readCLI(ctx, h, c, a)
	}
	return nil, cliError{"usage", 2}
}
func keyData(k *localkey.Key) any {
	return map[string]any{"identity": k.Identity(), "key_id": k.ID(), "algorithm": "ed25519", "public_key": base64.StdEncoding.EncodeToString(k.PublicKey())}
}
func selectSpace(c localConfig, id string) (localSpace, error) {
	for _, s := range c.Spaces {
		if s.ID == id {
			return s, nil
		}
	}
	return localSpace{}, cliError{"unknown_space", 2}
}
func selected(c localConfig, id string) ([]localSpace, error) {
	if id == "" {
		return c.Spaces, nil
	}
	s, e := selectSpace(c, id)
	if e != nil {
		return nil, e
	}
	return []localSpace{s}, nil
}
func openSpace(ctx context.Context, s localSpace) (*space.Repository, error) {
	r, e := localRepository(s)
	if e != nil {
		return nil, e
	}
	e = r.Sync(ctx)
	if e != nil {
		return r, e
	}
	if r.VerifiedPolicy() == nil {
		if d := r.Diagnostics(); len(d) > 0 {
			return r, &space.Error{Code: d[0].Code}
		}
		return r, &space.Error{Code: "no_verified_policy"}
	}
	p := r.VerifiedPolicy().Policy()
	if p.SpaceID != s.ID || p.Kind != s.Kind {
		return r, &space.Error{Code: "space_mismatch"}
	}
	return r, nil
}
func summary(s localSpace, r *space.Repository) any {
	out := map[string]any{"id": s.ID, "policy": r.VerifiedPolicy().Policy(), "policy_digest": r.VerifiedPolicy().Digest(), "cursor": r.Cursor(), "diagnostic_count": len(r.Diagnostics()), "diagnostics": r.Diagnostics()}
	if warnings := r.VerifiedPolicy().Policy().ResolverWarnings(); len(warnings) > 0 {
		out["resolver_warnings"] = warnings
	}
	return out
}

// gitCall always passes the process environment unchanged. It redacts transport
// stderr; callers configure transport, author and signing explicitly.
func gitCall(ctx context.Context, dir string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	cmd.Env = os.Environ()
	b, e := cmd.Output()
	if e != nil {
		return nil, &space.Error{Code: "git_failed", Command: args[0]}
	}
	return b, nil
}
func addSpace(ctx context.Context, h home, c *localConfig, a arguments, initialize bool) (any, error) {
	if len(a.pos) != 3 {
		return nil, cliError{"usage", 2}
	}
	if e := a.allow("remote", "branch", "genesis", "kind"); e != nil {
		return nil, e
	}
	remote, e := a.required("remote")
	if e != nil {
		return nil, e
	}
	// Local paths are relative to the caller, not the private clone parent used
	// as git's execution directory. Transport URLs and SCP syntax stay exact.
	if !filepath.IsAbs(remote) && !strings.Contains(remote, ":") {
		remote, e = filepath.Abs(remote)
		if e != nil {
			return nil, cliError{"invalid_configuration", 3}
		}
	}
	id := a.pos[2]
	if _, e := selectSpace(*c, id); e == nil {
		return nil, cliError{"duplicate_space", 3}
	}
	branch := a.flags["branch"]
	if branch == "" {
		branch = "main"
	}
	kind := a.flags["kind"]
	if kind == "" {
		kind = "project"
	}
	if kind != "agent" && kind != "project" && kind != "platform" {
		return nil, cliError{"usage", 2}
	}
	clone, cache := h.paths(id)
	for _, path := range []string{clone, cache} {
		resolved, e := canonicalPath(path)
		if e != nil || resolved != path {
			return nil, cliError{"invalid_configuration", 3}
		}
	}
	if repositoryAncestor(filepath.Dir(clone)) || repositoryAncestor(cache) {
		return nil, cliError{"home_inside_repository", 3}
	}
	s := localSpace{ID: id, Remote: remote, Branch: branch, ClonePath: clone, CachePath: cache, GenesisDigest: a.flags["genesis"], Kind: kind}
	var genesis space.SignedPolicy
	if initialize {
		if s.GenesisDigest != "" {
			return nil, cliError{"usage", 2}
		}
		k, e := h.key(*c)
		if e != nil {
			return nil, e
		}
		genesis, e = genesisPolicy(id, kind, k)
		if e != nil {
			return nil, e
		}
		canonical, e := space.NewCanonicalPolicy(genesis.Policy)
		if e != nil {
			return nil, e
		}
		s.GenesisDigest = sign.PolicyDigest(canonical.Bytes())
	} else if s.GenesisDigest == "" {
		return nil, cliError{"usage", 2}
	}
	next := *c
	next.Spaces = append(append([]localSpace{}, c.Spaces...), s)
	if _, e := h.encodeConfig(next); e != nil {
		return nil, e
	}
	if e := privateDir(filepath.Dir(clone)); e != nil {
		return nil, e
	}
	if initialize {
		if _, e := os.Lstat(clone); errors.Is(e, os.ErrNotExist) {
			if _, e = gitCall(ctx, filepath.Dir(clone), "clone", "--no-tags", "--", remote, filepath.Base(clone)); e != nil {
				return nil, e
			}
		} else {
			b, e := gitCall(ctx, clone, "remote", "get-url", "origin")
			if e != nil || strings.TrimSpace(string(b)) != remote {
				return nil, cliError{"clone_exists", 3}
			}
		}
		_, _, e = space.InitializePolicy(ctx, space.Git{Directory: clone, Environment: os.Environ()}, branch, genesis)
		if e != nil {
			return nil, e
		}
	} else {
		if _, e := os.Lstat(clone); errors.Is(e, os.ErrNotExist) {
			e = space.Clone(ctx, space.Git{Directory: clone, Environment: os.Environ()}, remote, branch)
			if e != nil {
				return nil, e
			}
		} else {
			b, e := gitCall(ctx, clone, "remote", "get-url", "origin")
			if e != nil || strings.TrimSpace(string(b)) != remote {
				return nil, cliError{"clone_exists", 3}
			}
		}
	}
	r, e := openSpace(ctx, s)
	if e != nil {
		return nil, e
	}
	if e = h.save(next); e != nil {
		return nil, e
	}
	*c = next
	return summary(s, r), nil
}
func genesisPolicy(id, kind string, k *localkey.Key) (space.SignedPolicy, error) {
	template, _, e := agentprofile.Load()
	if e != nil {
		return space.SignedPolicy{}, e
	}
	refs := []kernel.SchemaRef{}
	writerRefs := []*kernel.SchemaRef{nil}
	for _, raw := range agentprofile.Array(template["domain_schemas"]) {
		d := agentprofile.Object(raw)
		ref := kernel.SchemaRef{ID: d["id"].(string), Version: d["version"].(int64)}
		refs = append(refs, ref)
		copied := ref
		writerRefs = append(writerRefs, &copied)
	}
	p := space.Policy{Format: space.PolicyFormatV2, SpaceID: id, Kind: kind, Version: 1, Author: k.Identity(), Owners: []string{k.Identity()}, Readers: []space.Reader{{Identity: k.Identity(), Spaces: []string{}}}, Writers: []space.Writer{{Identity: k.Identity(), AdmissionClasses: []string{"machine_observation", "self_declaration", "semantic_inference"}, Schemas: writerRefs, Kinds: []string{"assertion", "source", "justification", "assessment", "revision"}}}, Keys: []space.SignedRegistration{{Registration: space.Registration{Identity: k.Identity(), Key: k.ID(), Alg: "ed25519", PublicKey: base64.StdEncoding.EncodeToString(k.PublicKey())}}}, Schemas: refs, Ceiling: "non-sensitive", Limits: space.Limits{MaxRecordBytes: 1000000, MaxFieldBytes: 65536}, Resolvers: []space.Resolver{}, Retention: space.Retention{OnOwnerRetire: "retain", OnOwnerRevoke: "deny"}}
	return space.EndorsePolicy(p, k)
}
func administer(ctx context.Context, h home, c localConfig, a arguments, action string) (any, error) {
	if e := a.allow("space", "identity", "public-key", "role"); e != nil {
		return nil, e
	}
	id, e := a.required("space")
	if e != nil {
		return nil, e
	}
	identity, e := a.required("identity")
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
	role := a.flags["role"]
	if action != "register" && role != "reader" && role != "writer" {
		return nil, cliError{"usage", 2}
	}
	if action == "register" && a.flags["role"] != "" || action != "register" && a.flags["public-key"] != "" {
		return nil, cliError{"usage", 2}
	}
	head, e := r.UpdatePolicy(ctx, k.Identity(), k, func(p *space.Policy) error {
		if action == "register" {
			public, e := base64.StdEncoding.Strict().DecodeString(a.flags["public-key"])
			if e != nil || len(public) != 32 {
				return cliError{"invalid_registration", 3}
			}
			keyID := sign.KeyID(public)
			for _, entry := range p.Keys {
				if entry.Registration.Key == keyID {
					return cliError{"duplicate_key", 3}
				}
			}
			p.Keys = append(p.Keys, space.SignedRegistration{Registration: space.Registration{Identity: identity, Key: keyID, Alg: "ed25519", PublicKey: base64.StdEncoding.EncodeToString(public)}})
			return nil
		}
		if role == "reader" {
			readers := []space.Reader{}
			for _, v := range p.Readers {
				if v.Identity != identity {
					readers = append(readers, v)
				}
			}
			if action == "grant" {
				readers = append(readers, space.Reader{Identity: identity, Spaces: []string{}})
			}
			p.Readers = readers
		} else {
			writers := []space.Writer{}
			for _, v := range p.Writers {
				if v.Identity != identity {
					writers = append(writers, v)
				}
			}
			if action == "grant" {
				refs := []*kernel.SchemaRef{nil}
				for _, ref := range p.Schemas {
					v := ref
					refs = append(refs, &v)
				}
				writers = append(writers, space.Writer{Identity: identity, AdmissionClasses: []string{"machine_observation", "self_declaration", "semantic_inference"}, Schemas: refs, Kinds: []string{"assertion", "source", "justification", "assessment", "revision"}})
			}
			p.Writers = writers
		}
		return nil
	})
	if e != nil {
		return nil, e
	}
	r, e = openSpace(ctx, s)
	if e != nil {
		return nil, e
	}
	return map[string]any{"commit": head, "space": summary(s, r)}, nil
}

// Compact reads keep the complete data envelope and show retained source details
// as decoded text. JSON output above always preserves the exact kernel payload.
func renderSourceDetails(out io.Writer, data any) {
	for _, rawSpace := range agentprofile.Array(agentprofile.Object(data)["spaces"]) {
		for _, rawView := range agentprofile.Array(agentprofile.Object(rawSpace)["views"]) {
			for _, rawSource := range agentprofile.Array(agentprofile.Object(rawView)["sources"]) {
				source := agentprofile.Object(rawSource)
				fmt.Fprintf(out, "source %v (%v)\n", source["ref"], source["availability"])
				if source["availability"] == "erased" {
					continue
				}
				fmt.Fprintf(out, "  owner: %v; object: %v; revision: %v; digest: %v\n", source["owner"], source["object"], source["revision"], source["digest"])
				locator := map[string]string{}
				origin, _ := source["origin"].(string)
				if json.Unmarshal([]byte(origin), &locator) == nil && len(locator) == 3 && locator["runtime"] != "" && locator["session"] != "" && locator["message"] != "" {
					fmt.Fprintf(out, "  runtime: %s; session: %s; message: %s\n", locator["runtime"], locator["session"], locator["message"])
				} else {
					fmt.Fprintf(out, "  origin: %s\n", origin)
				}
				excerpt := agentprofile.Object(source["excerpt"])
				if excerpt["state"] == "present" {
					fmt.Fprintf(out, "  excerpt:\n%s\n", excerpt["text"])
				}
			}
		}
	}
}
