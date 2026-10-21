package e2e_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type stage5Fixture struct {
	*fixture
	other                *agent
	platform1, platform2 project
	alpha, beta          project
	alphaAd, betaAd      string
	agents               []*agent
}

func newStage5(t *testing.T) *stage5Fixture {
	t.Helper()
	f := &fixture{t: t, root: t.TempDir()}
	f.allowedSigners = filepath.Join(f.root, "allowed_signers")
	f.owner = f.newAgentIdentity("owner-one", "o1/owner")
	f.a = f.newAgentIdentity("agent-one", "o1/agent:a1")
	o2 := f.newAgentIdentity("owner-two", "o2/owner")
	f.b = f.newAgentIdentity("agent-two", "o2/agent:b1")
	s := &stage5Fixture{fixture: f, other: o2, agents: []*agent{f.owner, f.a, o2, f.b}}
	s.platform1 = s.initSpace(f.owner, "o1/platform", "platform")
	s.platform2 = s.initSpace(o2, "o2/platform", "platform")
	s.alpha = s.initSpace(f.owner, "o1/project:alpha", "project")
	s.beta = s.initSpace(o2, "o2/project:beta", "project")
	for _, row := range []struct {
		owner, reader *agent
		spaces        []project
	}{{f.owner, f.a, []project{s.platform1, s.alpha}}, {o2, f.b, []project{s.platform2, s.beta}}} {
		for _, p := range row.spaces {
			s.register(row.owner, row.reader, p)
			for _, role := range []string{"reader", "writer"} {
				row.owner.run(0, "policy", "grant", "--space", p.id, "--identity", row.reader.identity, "--role", role)
			}
		}
	}
	// Public-key exchange is harness transport, never authority: each target
	// owner signs the foreign registration; reader grants are deliberately absent.
	s.register(f.owner, f.b, s.alpha)
	s.register(o2, f.a, s.beta)
	s.pin(f.a, s.platform1, "platform")
	s.pin(f.b, s.platform2, "platform")
	s.onlyConfigured(f.a, s.platform1.id)
	s.onlyConfigured(f.b, s.platform2.id)
	keys := map[string]bool{}
	for _, a := range s.agents {
		if keys[a.keyID] {
			t.Fatal("stage-5 principals share keys")
		}
		keys[a.keyID] = true
	}
	s.alphaAd, s.betaAd = s.advertise(f.owner, s.alpha), s.advertise(o2, s.beta)
	for _, row := range []struct {
		owner *agent
		p     project
	}{{f.owner, s.platform1}, {o2, s.platform2}} {
		// The exchanged files are opaque signed advertisements. The receiving
		// owner publishes through its own CLI, which supplies the outer signature.
		for _, ad := range []string{s.alphaAd, s.betaAd} {
			s.publish(row.owner, row.p, ad)
		}
	}
	return s
}

func (s *stage5Fixture) newPrincipal(name, identity string) *agent {
	a := s.newAgentIdentity(name, identity)
	s.agents = append(s.agents, a)
	return a
}

// Existing CLI helpers retain a test pointer. Bind it to each sequential
// subtest so a fixture refusal fails that subtest rather than its parent.
func (s *stage5Fixture) step(parent *testing.T, name string, run func(*testing.T)) {
	if !parent.Run(name, func(t *testing.T) {
		s.fixture.t = t
		for _, a := range s.agents {
			a.t = t
		}
		defer func() {
			s.fixture.t = parent
			for _, a := range s.agents {
				a.t = parent
			}
		}()
		run(t)
	}) {
		parent.FailNow()
	}
}

func (s *stage5Fixture) initSpace(owner *agent, id, kind string) project {
	s.t.Helper()
	p := project{id: id, remote: filepath.Join(s.root, hex.EncodeToString([]byte(id))+".git")}
	owner.git(s.root, "init", "--bare", "--initial-branch=main", p.remote)
	m := object(s.t, owner.run(0, "spaces", "init", id, "--remote", p.remote, "--kind", kind).Data, "id", "policy", "policy_digest", "cursor", "diagnostic_count", "diagnostics")
	p.pin, p.genesis = text(s.t, m["policy_digest"]), text(s.t, m["cursor"])
	return p
}

func (s *stage5Fixture) register(owner, reader *agent, p project) {
	s.t.Helper()
	owner.run(0, "keys", "register", "--space", p.id, "--identity", reader.identity, "--public-key", reader.publicKey)
}

func (s *stage5Fixture) pin(a *agent, p project, kind string) {
	s.t.Helper()
	a.run(0, "spaces", "add", p.id, "--remote", p.remote, "--genesis", p.pin, "--kind", kind)
}

func (s *stage5Fixture) discover(a *agent, p, platform project) {
	s.t.Helper()
	a.run(0, "spaces", "add", p.id, "--from-directory", platform.id)
	a.run(0, "sync", "--space", p.id)
	cfg := s.configured(a)[p.id]
	if text(s.t, cfg["genesis_digest"]) != p.pin || text(s.t, cfg["directory_space"]) != platform.id {
		s.t.Fatal("discovery lost the target pin or own directory association")
	}
}

func (s *stage5Fixture) advertise(a *agent, p project) string {
	s.t.Helper()
	file := filepath.Join(s.root, hex.EncodeToString([]byte(p.id))+"-advertisement.json")
	a.run(0, "directory", "advertise", "--space", p.id, "--out", file)
	return file
}

func (s *stage5Fixture) publish(a *agent, p project, file string) {
	s.t.Helper()
	a.run(0, "directory", "publish", "--space", p.id, "--entry", file)
}

func (s *stage5Fixture) configured(a *agent) map[string]map[string]json.RawMessage {
	s.t.Helper()
	m := object(s.t, a.run(0, "spaces", "list").Data, "spaces")
	out := map[string]map[string]json.RawMessage{}
	for _, raw := range array(s.t, m["spaces"]) {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil {
			s.t.Fatal(err)
		}
		keys := []string{"id", "remote", "branch", "clone_path", "cache_path", "genesis_digest", "kind"}
		if fields["directory_space"] != nil {
			keys = append(keys, "directory_space")
		}
		fields = object(s.t, raw, keys...)
		id := text(s.t, fields["id"])
		if out[id] != nil {
			s.t.Fatal("duplicate configured space")
		}
		for _, key := range []string{"clone_path", "cache_path"} {
			path := text(s.t, fields[key])
			rel, err := filepath.Rel(a.home, path)
			if err != nil || filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
				s.t.Fatal("stage-5 state escaped its home")
			}
		}
		out[id] = fields
	}
	return out
}

func (s *stage5Fixture) onlyConfigured(a *agent, ids ...string) {
	s.t.Helper()
	m := s.configured(a)
	if len(m) != len(ids) {
		s.t.Fatal("unexpected manual/discovered pins", m)
	}
	for _, id := range ids {
		if m[id] == nil {
			s.t.Fatal("missing configured pin", id)
		}
	}
}

func (s *stage5Fixture) configBytes(a *agent) []byte {
	s.t.Helper()
	b, err := os.ReadFile(filepath.Join(a.home, "config.json"))
	if err != nil {
		s.t.Fatal(err)
	}
	return b
}

func (s *stage5Fixture) sameConfig(a *agent, before []byte) {
	s.t.Helper()
	if !bytes.Equal(before, s.configBytes(a)) {
		s.t.Fatal("refusal changed configuration")
	}
}

func (s *stage5Fixture) noTargetState(a *agent, p project) {
	s.t.Helper()
	sum := sha256.Sum256([]byte(p.id))
	for _, dir := range []string{"clones", "caches"} {
		path := filepath.Join(a.home, dir, hex.EncodeToString(sum[:]))
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			s.t.Fatal("failed discovery retained target state", dir, err)
		}
	}
	entries, err := os.ReadDir(a.home)
	if err != nil {
		s.t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".directory-") {
			s.t.Fatal("failed discovery retained staging state")
		}
	}
}

func (s *stage5Fixture) state(a *agent, p project) publicationState {
	s.t.Helper()
	clone := text(s.t, s.configured(a)[p.id]["clone_path"])
	return publicationState{a.git(p.remote, "rev-parse", "main"), a.git(clone, "rev-parse", "HEAD"), a.git(clone, "rev-parse", "HEAD^{tree}"), a.git(clone, "write-tree"), a.git(clone, "status", "--porcelain", "--untracked-files=all"), a.git(clone, "rev-list", "--all", "--reflog", "--count")}
}

func (s *stage5Fixture) sameState(a *agent, p project, before publicationState) {
	s.t.Helper()
	if after := s.state(a, p); after != before {
		s.t.Fatalf("refusal changed publication state: before=%+v after=%+v", before, after)
	}
}

func (s *stage5Fixture) noRead(a *agent, p project, claim string) {
	s.t.Helper()
	before := s.configBytes(a)
	for _, args := range [][]string{{"recall", "*"}, {"explain", stage5AlphaID}} {
		r := a.start("", append(args, "--space", p.id, "--at", queryTime)...).finish(-1)
		if r.Error == nil {
			s.t.Fatalf("%s: target reader check bypassed; unauthorized read succeeded: %s", claim, r.Data)
		}
		refused(s.t, r, "not_authorized")
		if string(r.Data) != "null" || bytes.Contains(r.raw, []byte(stage5AlphaID)) || bytes.Contains(r.raw, []byte(stage5Excerpt)) || bytes.Contains(r.raw, []byte(stage5BetaID)) {
			s.t.Fatal("unauthorized response leaked record/source data", string(r.raw))
		}
	}
	s.sameConfig(a, before)
}

// Compare all projected semantic fields. Only Git cursor attribution and the
// caller's cursor-bound write token are removed: directory commits move those.
func (s *stage5Fixture) semanticView(a *agent, p project) []byte {
	s.t.Helper()
	r := readAt(a, "recall", "*", p.id)
	if len(readItems(s.t, r, p.id)) == 0 {
		s.t.Fatal("view-invariance control must be populated")
	}
	spaces, _ := readSpaces(s.t, r)
	var views []any
	if len(spaces) != 1 || json.Unmarshal(mustStage5JSON(s.t, spaces[0].Views), &views) != nil {
		s.t.Fatal("invalid invariant view")
	}
	for _, raw := range views {
		v := raw.(map[string]any)
		for _, rawItem := range v["items"].([]any) {
			i := rawItem.(map[string]any)
			delete(i, "write_token")
			delete(i["source"].(map[string]any), "cursor")
		}
	}
	return mustStage5JSON(s.t, views)
}

func mustStage5JSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (s *stage5Fixture) assertProject(a *agent, p project, id, value, issuer string, withSource bool) {
	s.t.Helper()
	for _, command := range []string{"recall", "explain"} {
		target := id
		if command == "recall" {
			target = "*"
		}
		r := readAt(a, command, target, p.id)
		onlyRecord(s.t, readItems(s.t, r, p.id), id, value, issuer)
		i := item(s.t, r, p.id, id, 1)
		spaces, _ := readSpaces(s.t, r)
		v := object(s.t, spaces[0].Views[0], "type", "semantic_profile", "projection_rule", "evidence_policy", "policy", "data_classification", "items", "sources", "currentness", "historical", "review_required", "explanation", "cutoffs", "changes")
		sources := array(s.t, v["sources"])
		if !withSource {
			if len(sources) != 0 || len(refs(s.t, i["source_refs"])) != 0 {
				s.t.Fatal("assumption acquired an invented source")
			}
			continue
		}
		want := recordRef{id + ":source", 1}
		if len(sources) != 1 || !reflect.DeepEqual(refs(s.t, i["source_refs"]), []recordRef{want}) {
			s.t.Fatal("decision lost its unique source citation")
		}
		entry := object(s.t, sources[0], "ref", "issuer", "submitter", "representation_ref", "admission_class", "owner", "source_kind", "object", "revision", "digest", "provenance", "origin", "original_issuer", "carrier", "availability", "excerpt")
		var locator map[string]string
		if err := json.Unmarshal([]byte(text(s.t, entry["origin"])), &locator); err != nil || !reflect.DeepEqual(locator, map[string]string{"runtime": "runtime", "session": "stage5", "message": "message:decision"}) {
			s.t.Fatal("cross-owner locator changed", locator, err)
		}
		excerpt := object(s.t, entry["excerpt"], "state", "text")
		digest := object(s.t, entry["digest"], "algorithm", "value")
		sum := sha256.Sum256([]byte(stage5Excerpt))
		if ref(s.t, entry["ref"]) != want || text(s.t, entry["availability"]) != "unavailable" || text(s.t, entry["owner"]) != "runtime:runtime" || text(s.t, entry["source_kind"]) != "artifact" || text(s.t, entry["object"]) != "session:stage5" || text(s.t, entry["revision"]) != "message:decision" || text(s.t, entry["issuer"]) != issuer || text(s.t, entry["submitter"]) != issuer || text(s.t, entry["original_issuer"]) != issuer || text(s.t, entry["provenance"]) != "reported" || text(s.t, excerpt["state"]) != "present" || text(s.t, excerpt["text"]) != stage5Excerpt || text(s.t, digest["algorithm"]) != "sha256-bytes-v1" || text(s.t, digest["value"]) != hex.EncodeToString(sum[:]) {
			s.t.Fatal("cross-owner source attribution/locator/excerpt/digest changed", string(sources[0]))
		}
	}
}

// This independent encoder is only for an adversarial object. All its wire
// strings are ASCII and integers are exact; encoding/json key order gives the
// canonical bytes for this bounded fixture without importing application APIs.
func (s *stage5Fixture) forgeWriterEntry() {
	s.t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		s.t.Fatal(err)
	}
	s.owner.run(0, "keys", "register", "--space", s.platform1.id, "--identity", s.a.identity, "--public-key", base64.StdEncoding.EncodeToString(public))
	adFile := s.advertise(s.owner, s.platform1)
	ad, err := os.ReadFile(adFile)
	if err != nil {
		s.t.Fatal(err)
	}
	var advertisement any
	if err := json.Unmarshal(ad, &advertisement); err != nil {
		s.t.Fatal(err)
	}
	entry := map[string]any{"format": "swarma-memory-directory/1", "directory_space": s.platform1.id, "space_id": s.platform1.id, "version": 1, "previous": nil, "status": "active", "advertisement": advertisement, "author": s.a.identity}
	canonical := mustStage5JSON(s.t, entry)
	framed := append([]byte("swarma-memory-directory/1\x00"), canonical...)
	signature := ed25519.Sign(private, framed)
	if !ed25519.Verify(public, framed, signature) {
		s.t.Fatal("adversarial signature fixture invalid")
	}
	keyHash := sha256.Sum256(public)
	wire := map[string]any{"entry": entry, "signature": map[string]any{"purpose": "swarma-memory-directory/1", "key": "ed25519:sha256:" + hex.EncodeToString(keyHash[:]), "alg": "ed25519", "value": base64.StdEncoding.EncodeToString(signature)}}
	s.a.run(0, "sync", "--space", s.platform1.id)
	clone := text(s.t, s.configured(s.a)[s.platform1.id]["clone_path"])
	path := "directory/" + hex.EncodeToString([]byte(s.platform1.id)) + "/1.json"
	if err := os.MkdirAll(filepath.Dir(filepath.Join(clone, path)), 0755); err != nil {
		s.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(clone, path), mustStage5JSON(s.t, wire), 0644); err != nil {
		s.t.Fatal(err)
	}
	s.a.git(clone, "add", "--", path)
	s.a.git(clone, "commit", "-S", "-m", "adversarial directory publisher fixture")
	s.a.git(clone, "push", "origin", "HEAD:refs/heads/main")
}
