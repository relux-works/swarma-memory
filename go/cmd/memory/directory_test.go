package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/swarma-memory/go/agentprofile"
	"github.com/relux-works/swarma-memory/go/sign"
	"github.com/relux-works/swarma-memory/go/sign/localkey"
	"github.com/relux-works/swarma-memory/go/space"
)

// Each test owns its complete filesystem, Git environment and record/SSH keys.
// Only the immutable subprocess binary is shared, so tests can run in parallel.
type directoryHarness struct {
	*cliHarness
	platform, platformRemote, platformPin string
}

func newDirectory(t *testing.T) *directoryHarness {
	h := newCLI(t)
	d := &directoryHarness{cliHarness: h, platform: "space:platform", platformRemote: filepath.Join(h.root, "platform.git")}
	h.git(h.root, "init", "--bare", "--initial-branch=main", d.platformRemote)
	m, _ := h.invoke(h.owner, 0, "spaces", "init", d.platform, "--remote", d.platformRemote, "--kind", "platform")
	d.platformPin = agentprofile.Object(m["data"])["policy_digest"].(string)
	m, _ = h.invoke(h.reader, 0, "keys", "init", "--identity", "agent:reader")
	h.invoke(h.owner, 0, "keys", "register", "--space", d.platform, "--identity", "agent:reader", "--public-key", agentprofile.Object(m["data"])["public_key"].(string))
	h.invoke(h.owner, 0, "policy", "grant", "--space", d.platform, "--identity", "agent:reader", "--role", "reader")
	d.pinPlatform(h.reader)
	return d
}
func (d *directoryHarness) pinPlatform(home string) {
	d.t.Helper()
	d.invoke(home, 0, "spaces", "add", d.platform, "--remote", d.platformRemote, "--genesis", d.platformPin, "--kind", "platform")
}
func (h *cliHarness) localKey(home string) *localkey.Key {
	h.t.Helper()
	k, e := localkey.Load(os.DirFS(home), "localkey.json")
	if e != nil {
		h.t.Fatal(e)
	}
	return k
}
func (h *cliHarness) localRepo(home, id string) *space.Repository {
	h.t.Helper()
	s, e := selectSpace(h.config(home), id)
	if e != nil {
		h.t.Fatal(e)
	}
	template, schemas, e := agentprofile.Load()
	if e != nil {
		h.t.Fatal(e)
	}
	r, e := space.Open(space.Config{Git: space.Git{Directory: s.ClonePath, Environment: h.env}, Branch: s.Branch, CacheDirectory: s.CachePath, GenesisDigest: s.GenesisDigest, Template: template, Schemas: schemas, Mint: agentprofile.Mint, Profile: agentprofile.Configure})
	if e != nil {
		h.t.Fatal(e)
	}
	if e = r.Sync(context.Background()); e != nil {
		h.t.Fatal(e)
	}
	return r
}
func (h *cliHarness) ad(home, id string) space.SignedAdvertisement {
	h.t.Helper()
	s, e := selectSpace(h.config(home), id)
	if e != nil {
		h.t.Fatal(e)
	}
	k := h.localKey(home)
	a, e := h.localRepo(home, id).Advertisement(k.Identity(), space.Location{Remote: s.Remote, Branch: s.Branch}, []space.Binding{}, k)
	if e != nil {
		h.t.Fatal(e)
	}
	return a
}
func (h *cliHarness) resign(a space.Advertisement, k *localkey.Key) space.SignedAdvertisement {
	h.t.Helper()
	c, e := space.NewCanonicalAdvertisement(a)
	if e != nil {
		h.t.Fatal(e)
	}
	sig, e := k.SignAdvertisement(c)
	if e != nil {
		h.t.Fatal(e)
	}
	return space.SignedAdvertisement{Advertisement: a, Signature: sig}
}
func (h *cliHarness) jsonFile(value any) string {
	h.t.Helper()
	b, e := json.Marshal(value)
	if e != nil {
		h.t.Fatal(e)
	}
	f, e := os.CreateTemp(h.root, "input-*.json")
	if e != nil {
		h.t.Fatal(e)
	}
	if _, e = f.Write(b); e != nil {
		h.t.Fatal(e)
	}
	if e = f.Close(); e != nil {
		h.t.Fatal(e)
	}
	return f.Name()
}
func (d *directoryHarness) publish(a space.SignedAdvertisement) {
	d.t.Helper()
	d.invoke(d.owner, 0, "directory", "publish", "--space", d.platform, "--entry", d.jsonFile(a))
}
func (d *directoryHarness) addTarget(code int) map[string]any {
	d.t.Helper()
	m, _ := d.invoke(d.reader, code, "spaces", "add", "space:test", "--from-directory", d.platform)
	return m
}
func (h *cliHarness) configBytes(home string) string {
	h.t.Helper()
	b, e := os.ReadFile(filepath.Join(home, "config.json"))
	if e != nil {
		h.t.Fatal(e)
	}
	return string(b)
}
func (d *directoryHarness) unchangedConfig(before string) {
	d.t.Helper()
	if after := d.configBytes(d.reader); after != before {
		d.t.Fatal("failed discovery changed config")
	}
}
func expectDirectoryCode(t *testing.T, m map[string]any, want string) {
	t.Helper()
	if errorCodeOf(m) != want {
		t.Fatalf("code=%v want=%s", errorCodeOf(m), want)
	}
}
func (d *directoryHarness) grantTarget() {
	key := d.localKey(d.reader)
	policy := d.localRepo(d.owner, "space:test").VerifiedPolicy().Policy()
	found := false
	for _, entry := range policy.Keys {
		if entry.Registration.Key == key.ID() {
			found = true
		}
	}
	if !found {
		d.invoke(d.owner, 0, "keys", "register", "--space", "space:test", "--identity", key.Identity(), "--public-key", base64.StdEncoding.EncodeToString(key.PublicKey()))
	}

	d.invoke(d.owner, 0, "policy", "grant", "--space", "space:test", "--identity", "agent:reader", "--role", "reader")
}

// Discovery supplies pins and locations only: an isolated second home needs a
// target grant to recall; withdrawal/revocation leave independent pins intact.
func TestDirectoryDiscoveryLifecycle(t *testing.T) {
	t.Parallel()
	d := newDirectory(t)
	h := d.cliHarness
	h.appendRecord("record:directory", "discovered evidence")
	target := h.localRepo(h.owner, "space:test")
	before := target.Cursor()
	platformSnapshot := stringMustJSON(t, h.localRepo(h.owner, d.platform).Snapshot())
	targetSnapshot := stringMustJSON(t, target.Snapshot())
	adFile := filepath.Join(h.root, "advertisement.json")
	h.invoke(h.owner, 0, "directory", "advertise", "--space", "space:test", "--out", adFile)
	h.invoke(h.owner, 0, "directory", "publish", "--space", d.platform, "--entry", adFile)
	if after := h.localRepo(h.owner, "space:test").Cursor(); after != before {
		t.Fatal("directory changed target history")
	}
	if platformSnapshot != stringMustJSON(t, h.localRepo(h.owner, d.platform).Snapshot()) || targetSnapshot != stringMustJSON(t, h.localRepo(h.owner, "space:test").Snapshot()) {
		t.Fatal("directory changed kernel state")
	}
	h.invoke(h.reader, 0, "directory", "list", "--space", d.platform)
	h.invoke(h.reader, 0, "directory", "show", "--space", d.platform)
	d.addTarget(0)
	m, _ := h.invoke(h.reader, 3, "recall", "*", "--space", "space:test")
	expectDirectoryCode(t, m, "not_authorized")
	d.grantTarget()
	_, raw := h.invoke(h.reader, 0, "recall", "discovered", "--space", "space:test")
	if !strings.Contains(raw, "discovered evidence") {
		t.Fatal(raw)
	}
	h.invoke(h.owner, 0, "policy", "revoke", "--space", "space:test", "--identity", "agent:reader", "--role", "reader")
	m, _ = h.invoke(h.reader, 3, "recall", "*", "--space", "space:test")
	expectDirectoryCode(t, m, "not_authorized")
	d.grantTarget()
	h.invoke(h.owner, 0, "directory", "withdraw", "--space", d.platform, "--space-id", "space:test")
	_, raw = h.invoke(h.reader, 0, "sync", "--space", "space:test")
	if !strings.Contains(raw, "directory_withdrawn") {
		t.Fatal(raw)
	}
	h.invoke(h.reader, 0, "recall", "discovered", "--space", "space:test")
	// Manual target configuration succeeds without any active directory entry.
	manual := filepath.Join(h.root, "manual")
	h.invoke(manual, 0, "keys", "init", "--identity", "agent:reader")
	h.invoke(manual, 0, "spaces", "add", "space:test", "--remote", h.remote, "--genesis", h.pin)
	h.invoke(h.owner, 0, "keys", "register", "--space", "space:test", "--identity", "agent:reader", "--public-key", base64.StdEncoding.EncodeToString(h.localKey(manual).PublicKey()))
	h.invoke(manual, 0, "recall", "discovered")
	// A wiped persistent agent has only the platform pin and its re-created key.
	d.publish(h.ad(h.owner, "space:test"))
	if e := os.RemoveAll(h.reader); e != nil {
		t.Fatal(e)
	}
	h.invoke(h.reader, 0, "keys", "init", "--identity", "agent:reader")
	h.invoke(h.owner, 0, "keys", "register", "--space", d.platform, "--identity", "agent:reader", "--public-key", base64.StdEncoding.EncodeToString(h.localKey(h.reader).PublicKey()))
	d.grantTarget()
	d.pinPlatform(h.reader)
	d.addTarget(0)
	h.invoke(h.reader, 0, "recall", "discovered", "--space", "space:test")
	// Relocation accepts the same genesis and preserves descent from the old cursor.
	old := h.localRepo(h.reader, "space:test").Cursor()
	moved := filepath.Join(h.root, "moved.git")
	h.git(h.root, "clone", "--bare", "--", h.remote, moved)
	a := h.ad(h.owner, "space:test")
	a.Advertisement.Git.Remote = moved
	d.publish(h.resign(a.Advertisement, h.localKey(h.owner)))
	h.invoke(h.reader, 0, "spaces", "update", "space:test", "--from-directory", d.platform)
	s, _ := selectSpace(h.config(h.reader), "space:test")
	if s.Remote != moved || h.localRepo(h.reader, "space:test").Cursor() != old {
		t.Fatal("relocation lost cursor or location")
	}
	h.invoke(h.reader, 0, "recall", "discovered", "--space", "space:test")
}

// Invalid target pins, metadata, owner signatures and rollback floors never
// publish config or a clone/cache; every refusal has a usable directory neighbour.
func TestDirectoryTargetRefusals(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, code string
		change     func(*space.Advertisement, *directoryHarness)
		signer     bool
	}{
		{"genesis", "directory_mismatch", func(a *space.Advertisement, d *directoryHarness) {
			a.GenesisDigest = "sha256:" + strings.Repeat("0", 64)
		}, false},
		{"id", "directory_mismatch", func(a *space.Advertisement, d *directoryHarness) { a.SpaceID = "space:other" }, false},
		{"kind", "directory_mismatch", func(a *space.Advertisement, d *directoryHarness) { a.Kind = "agent" }, false},
		{"observed-digest", "directory_mismatch", func(a *space.Advertisement, d *directoryHarness) {
			a.ObservedPolicy.Digest = "sha256:" + strings.Repeat("0", 64)
		}, false},
		{"rollback", "directory_mismatch", func(a *space.Advertisement, d *directoryHarness) { a.ObservedPolicy.Version++ }, false},
		{"non-owner", "directory_mismatch", func(a *space.Advertisement, d *directoryHarness) {
			d.invoke(d.owner, 0, "keys", "register", "--space", "space:test", "--identity", "agent:reader", "--public-key", base64.StdEncoding.EncodeToString(d.localKey(d.reader).PublicKey()))
			p := d.localRepo(d.owner, "space:test").VerifiedPolicy()
			a.ObservedPolicy = space.PolicyPin{Version: p.Policy().Version, Digest: p.Digest()}
			a.Author = "agent:reader"
		}, true},
		{"helper", "directory_transport", func(a *space.Advertisement, d *directoryHarness) { a.Git.Remote = "ext::false" }, false},
		{"option", "directory_transport", func(a *space.Advertisement, d *directoryHarness) { a.Git.Remote = "-bad" }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := newDirectory(t)
			good := d.ad(d.owner, "space:test")
			d.publish(good)
			// A second valid entry stays readable when this head cannot be consumed.
			neighbour := good.Advertisement
			neighbour.SpaceID = "space:neighbour"
			d.publish(d.resign(neighbour, d.localKey(d.owner)))
			bad := good.Advertisement
			tc.change(&bad, d)
			k := d.localKey(d.owner)
			if tc.signer {
				k = d.localKey(d.reader)
			}
			d.publish(d.resign(bad, k))
			before := d.configBytes(d.reader)
			id := bad.SpaceID
			m, _ := d.invoke(d.reader, 3, "spaces", "add", id, "--from-directory", d.platform)
			expectDirectoryCode(t, m, tc.code)
			d.unchangedConfig(before)
			clone, cache := (home{config: d.reader, state: d.reader}).paths(id)
			for _, p := range []string{clone, cache} {
				if _, e := os.Lstat(p); !os.IsNotExist(e) {
					t.Fatalf("refusal stranded state: %s", filepath.Base(p))
				}
			}
			_, raw := d.invoke(d.reader, 0, "directory", "show", "--space", d.platform, "--space-id", "space:neighbour")
			if !strings.Contains(raw, "active") {
				t.Fatal(raw)
			}
		})
	}
}

func (d *directoryHarness) forgedEntry(id string, k *localkey.Key) space.SignedDirectory {
	d.t.Helper()
	ad := d.ad(d.owner, "space:test").Advertisement
	ad.SpaceID = id
	a := d.resign(ad, d.localKey(d.owner))
	entry := space.DirectoryEntry{Format: sign.DirectoryPurpose, DirectorySpace: d.platform, SpaceID: id, Version: 1, Status: "active", Advertisement: &a, Author: k.Identity()}
	c, e := space.NewCanonicalDirectory(entry)
	if e != nil {
		d.t.Fatal(e)
	}
	sig, e := k.SignDirectory(c)
	if e != nil {
		d.t.Fatal(e)
	}
	return space.SignedDirectory{Entry: entry, Signature: sig}
}
func (d *directoryHarness) plant(files map[string]any, remove string) {
	d.t.Helper()
	s, _ := selectSpace(d.config(d.owner), d.platform)
	d.invoke(d.owner, 0, "sync", "--space", d.platform)
	for p, v := range files {
		path := filepath.Join(s.ClonePath, p)
		if e := os.MkdirAll(filepath.Dir(path), 0755); e != nil {
			d.t.Fatal(e)
		}
		b, e := json.Marshal(v)
		if e != nil {
			d.t.Fatal(e)
		}
		if e = os.WriteFile(path, b, 0644); e != nil {
			d.t.Fatal(e)
		}
	}
	if remove != "" {
		if e := os.Remove(filepath.Join(s.ClonePath, remove)); e != nil {
			d.t.Fatal(e)
		}
	}
	d.git(s.ClonePath, "add", "--", "directory")
	d.git(s.ClonePath, "commit", "-S", "-m", "directory validation fixture")
	d.git(s.ClonePath, "push", "origin", "HEAD:main")
}

// A registered platform writer cannot publish; disabling the historical owner
// check admits this exact forgery and must break this regression witness.
func TestDirectoryForgedWriter(t *testing.T) {
	t.Parallel()
	d := newDirectory(t)
	d.publish(d.ad(d.owner, "space:test"))
	d.invoke(d.owner, 0, "policy", "grant", "--space", d.platform, "--identity", "agent:reader", "--role", "writer")
	ad := d.ad(d.owner, "space:test")
	remoteHead := d.git(d.platformRemote, "rev-parse", "main")
	m, _ := d.invoke(d.reader, 3, "directory", "publish", "--space", d.platform, "--entry", d.jsonFile(ad))
	expectDirectoryCode(t, m, "directory_unauthorized")
	if d.git(d.platformRemote, "rev-parse", "main") != remoteHead {
		t.Fatal("writer published through CLI")
	}
	forged := d.forgedEntry("space:forged", d.localKey(d.reader))
	before := d.configBytes(d.reader)
	d.plant(map[string]any{space.DirectoryPath(forged.Entry): forged}, "")
	_, raw := d.invoke(d.reader, 0, "directory", "list", "--space", d.platform)
	if !strings.Contains(raw, `"code":"directory_unauthorized"`) || strings.Contains(raw, `"space_id":"space:forged"`) {
		t.Fatal("forged publisher admitted", raw)
	}
	d.unchangedConfig(before)
	d.addTarget(0)
}

// Purpose confusion, closed-schema extensions, transplants, sequence forks and
// accepted-file rewrites remain isolated from a valid, usable entry.
func TestDirectoryReplayRefusals(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"outer-purpose", "inner-purpose", "transplant", "extension", "sequence", "rewrite", "delete"} {
		t.Run(mode, func(t *testing.T) {
			d := newDirectory(t)
			d.publish(d.ad(d.owner, "space:test"))
			before := d.configBytes(d.reader)
			forged := d.forgedEntry("space:bad", d.localKey(d.owner))
			path := space.DirectoryPath(forged.Entry)
			want := ""
			var value any = forged
			remove := ""
			switch mode {
			case "outer-purpose":
				forged.Signature.Purpose = sign.AdvertisementPurpose
				want = "purpose_mismatch"
				value = forged
			case "inner-purpose":
				forged.Entry.Advertisement.Signature.Purpose = sign.DirectoryPurpose
				want = "purpose_mismatch"
				value = forged
			case "transplant":
				forged.Entry.DirectorySpace = "space:elsewhere"
				want = "directory_mismatch"
				value = forged
			case "extension":
				b, _ := json.Marshal(forged)
				var m map[string]any
				_ = json.Unmarshal(b, &m)
				m["access"] = []string{"read"}
				value = m
				want = "invalid_shape"
			case "sequence":
				forged.Entry.Version = 2
				prev := "sha256:" + strings.Repeat("0", 64)
				forged.Entry.Previous = &prev
				c, e := space.NewCanonicalDirectory(forged.Entry)
				if e != nil {
					t.Fatal(e)
				}
				forged.Signature, e = d.localKey(d.owner).SignDirectory(c)
				if e != nil {
					t.Fatal(e)
				}
				path = space.DirectoryPath(forged.Entry)
				value = forged
				want = "directory_sequence"
			case "rewrite", "delete":
				accepted := d.forgedEntry("space:accepted", d.localKey(d.owner))
				path = space.DirectoryPath(accepted.Entry)
				d.plant(map[string]any{path: accepted}, "")
				want = "directory_rewritten"
				value = forged
				if mode == "delete" {
					remove = path
				}
			}
			files := map[string]any{path: value}
			if remove != "" {
				files = map[string]any{}
			}
			d.plant(files, remove)
			_, raw := d.invoke(d.reader, 0, "directory", "list", "--space", d.platform)
			if !strings.Contains(raw, `"code":"`+want+`"`) {
				t.Fatal(want, raw)
			}
			if mode == "rewrite" || mode == "delete" {
				if !strings.Contains(raw, `"space_id":"space:accepted"`) {
					t.Fatal("rewrite displaced accepted entry", raw)
				}
			}
			d.unchangedConfig(before)
			d.addTarget(0)
		})
	}
}

// Withdrawal blocks new configuration but never erases the existing reader pin;
// a changed genesis also refuses without silently re-pinning an existing target.
func TestDirectoryWithdrawAndPinConflict(t *testing.T) {
	t.Parallel()
	d := newDirectory(t)
	good := d.ad(d.owner, "space:test")
	d.publish(good)
	d.invoke(d.owner, 0, "directory", "withdraw", "--space", d.platform, "--space-id", "space:test")
	before := d.configBytes(d.reader)
	expectDirectoryCode(t, d.addTarget(3), "directory_withdrawn")
	d.unchangedConfig(before)
	d.publish(good)
	d.addTarget(0)
	before = d.configBytes(d.reader)
	good.Advertisement.GenesisDigest = "sha256:" + strings.Repeat("0", 64)
	d.publish(d.resign(good.Advertisement, d.localKey(d.owner)))
	m, _ := d.invoke(d.reader, 3, "spaces", "update", "space:test", "--from-directory", d.platform)
	expectDirectoryCode(t, m, "genesis_conflict")
	d.unchangedConfig(before)
}

// Qualified policies accept named foreign readers and owner-attested keys,
// reject unqualified grants/keys and foreign writers, and forbid promotion.
func TestDirectoryOwnerQualification(t *testing.T) {
	t.Parallel()
	h := newCLI(t)
	a := filepath.Join(h.root, "a")
	b := filepath.Join(h.root, "b")
	h.invoke(a, 0, "keys", "init", "--identity", "a/agent:owner")
	m, _ := h.invoke(b, 0, "keys", "init", "--identity", "b/agent:owner")
	public := agentprofile.Object(m["data"])["public_key"].(string)
	remotes := map[string]string{}
	for _, pair := range [][2]string{{a, "space:a"}, {b, "space:b"}} {
		remote := filepath.Join(h.root, pair[1]+".git")
		h.git(h.root, "init", "--bare", "--initial-branch=main", remote)
		h.invoke(pair[0], 0, "spaces", "init", pair[1], "--remote", remote)
		remotes[pair[1]] = remote
	}
	h.invoke(a, 0, "keys", "register", "--space", "space:a", "--identity", "b/agent:owner", "--public-key", public)
	h.invoke(a, 0, "policy", "grant", "--space", "space:a", "--identity", "b/agent:owner", "--role", "reader")
	old := h.git(remotes["space:a"], "rev-parse", "main")
	config := h.configBytes(a)
	for _, args := range [][]string{{"policy", "grant", "--space", "space:a", "--identity", "b/agent:owner", "--role", "writer"}, {"policy", "grant", "--space", "space:a", "--identity", "agent:bare", "--role", "reader"}, {"keys", "register", "--space", "space:a", "--identity", "agent:bare", "--public-key", base64.StdEncoding.EncodeToString(h.localKey(h.owner).PublicKey())}} {
		m, _ := h.invoke(a, 3, args...)
		want := "identity_owner_mismatch"
		if args[0] == "policy" && args[len(args)-1] == "writer" {
			want = "cross_owner_writer"
		}
		expectDirectoryCode(t, m, want)
		if h.configBytes(a) != config || h.git(remotes["space:a"], "rev-parse", "main") != old {
			t.Fatal("refused owner mutation persisted")
		}
	}
	s, _ := selectSpace(h.config(a), "space:a")
	h.invoke(b, 0, "spaces", "add", "space:a", "--remote", s.Remote, "--genesis", s.GenesisDigest)
	h.invoke(a, 0, "add", "assertion", "--id", "record:foreign", "--space", "space:a", "--content", "readable foreign positive control", "--idempotency-key", "foreign-record")
	h.invoke(b, 0, "recall", "foreign", "--space", "space:a")
	beforePromotion := h.configBytes(b)
	targetHead := h.git(remotes["space:b"], "rev-parse", "main")
	m, _ = h.invoke(b, 3, "promote", "record:foreign", "--space", "space:a", "--to", "space:b", "--idempotency-key", "cross-owner")
	expectDirectoryCode(t, m, "cross_owner_promotion")
	if h.configBytes(b) != beforePromotion || h.git(remotes["space:b"], "rev-parse", "main") != targetHead {
		t.Fatal("refused promotion changed config or target")
	}

	h.invoke(b, 0, "add", "assertion", "--space", "space:b", "--content", "local positive control", "--idempotency-key", "own-write")
}

// Removing a publisher from the current owner set makes its otherwise valid
// historical entry stale; independently pinned target sync still succeeds.
func TestDirectoryRemovedPublisher(t *testing.T) {
	t.Parallel()
	d := newDirectory(t)
	d.publish(d.ad(d.owner, "space:test"))
	d.grantTarget()
	d.addTarget(0)
	repo := d.localRepo(d.owner, d.platform)
	k := d.localKey(d.owner)
	_, e := repo.UpdatePolicy(context.Background(), k.Identity(), k, func(p *space.Policy) error { p.Owners = []string{"agent:reader"}; return nil })
	if e != nil {
		t.Fatal(e)
	}
	before := d.configBytes(d.reader)
	m, _ := d.invoke(d.reader, 3, "spaces", "update", "space:test", "--from-directory", d.platform)
	expectDirectoryCode(t, m, "directory_stale")
	d.unchangedConfig(before)
	_, raw := d.invoke(d.reader, 0, "sync", "--space", "space:test")
	if !strings.Contains(raw, "directory_stale") {
		t.Fatal(raw)
	}
	_, raw = d.invoke(d.reader, 0, "directory", "show", "--space", d.platform, "--space-id", "space:test")
	if !strings.Contains(raw, `"state":"stale"`) {
		t.Fatal(raw)
	}
	// New discovery also refuses, with the same platform pin and owner reader.
	fresh := filepath.Join(d.root, "fresh")
	d.invoke(fresh, 0, "keys", "init", "--identity", "agent:reader")
	newOwner := d.localKey(d.reader)
	repo = d.localRepo(d.reader, d.platform)
	public := d.localKey(fresh)
	_, e = repo.UpdatePolicy(context.Background(), newOwner.Identity(), newOwner, func(p *space.Policy) error {
		p.Keys = append(p.Keys, space.SignedRegistration{Registration: space.Registration{Identity: public.Identity(), Key: public.ID(), Alg: "ed25519", PublicKey: base64.StdEncoding.EncodeToString(public.PublicKey())}})
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	d.pinPlatform(fresh)
	m, _ = d.invoke(fresh, 3, "spaces", "add", "space:test", "--from-directory", d.platform)
	expectDirectoryCode(t, m, "directory_stale")
}

// Relocation refuses a remote lacking the old first-parent cursor, even though
// its genesis and advertised policy floor verify; config/cache remain unchanged.
func TestDirectoryRelocationRejectsRewrite(t *testing.T) {
	t.Parallel()
	d := newDirectory(t)
	d.publish(d.ad(d.owner, "space:test"))
	d.addTarget(0)
	d.appendRecord("record:after-genesis", "descent guard")
	d.invoke(d.reader, 0, "sync", "--space", "space:test")
	s, _ := selectSpace(d.config(d.reader), "space:test")
	cached, e := os.ReadFile(filepath.Join(s.CachePath, "index.json"))
	if e != nil {
		t.Fatal(e)
	}
	moved := filepath.Join(d.root, "rewound.git")
	d.git(d.root, "clone", "--bare", "--", d.remote, moved)
	d.git(moved, "update-ref", "refs/heads/main", d.genesis)
	ad := d.ad(d.owner, "space:test")
	ad.Advertisement.Git.Remote = moved
	d.publish(d.resign(ad.Advertisement, d.localKey(d.owner)))
	before := d.configBytes(d.reader)
	m, _ := d.invoke(d.reader, 4, "spaces", "update", "space:test", "--from-directory", d.platform)
	expectDirectoryCode(t, m, "history_rewritten")
	d.unchangedConfig(before)
	after, e := os.ReadFile(filepath.Join(s.CachePath, "index.json"))
	if e != nil || string(after) != string(cached) {
		t.Fatal("failed relocation changed cursor")
	}
	d.invoke(d.reader, 0, "sync", "--space", "space:test")
}

// A real advertised policy-v2 floor rejects a clone rolled back to genesis;
// a valid neighbour is still discoverable and the refused config is unchanged.
func TestDirectoryObservedRollback(t *testing.T) {
	t.Parallel()
	d := newDirectory(t)
	d.grantTarget()
	ad := d.ad(d.owner, "space:test")
	if ad.Advertisement.ObservedPolicy.Version <= 1 {
		t.Fatal("missing floor")
	}
	d.publish(ad)
	neighbour := ad.Advertisement
	neighbour.SpaceID = "space:neighbour"
	d.publish(d.resign(neighbour, d.localKey(d.owner)))
	d.git(d.remote, "update-ref", "refs/heads/main", d.genesis)
	before := d.configBytes(d.reader)
	expectDirectoryCode(t, d.addTarget(3), "directory_mismatch")
	d.unchangedConfig(before)
	d.invoke(d.reader, 0, "directory", "show", "--space", d.platform, "--space-id", "space:neighbour")
}

// Bindings are explicit sorted lookup keys, never inferred agent identities or
// ACLs; unrecognized fields, unsorted pairs and duplicate pairs are rejected.
func TestDirectoryBindings(t *testing.T) {
	t.Parallel()
	d := newDirectory(t)
	// An owner label with an unregistered replacement key cannot export an ad.
	replacement, e := localkey.Generate("agent:owner")
	if e != nil {
		t.Fatal(e)
	}
	before := d.configBytes(d.owner)
	_, e = d.localRepo(d.owner, "space:test").Advertisement(replacement.Identity(), space.Location{Remote: d.remote, Branch: "main"}, []space.Binding{}, replacement)
	if e == nil || classify(e).Code != "directory_unauthorized" {
		t.Fatal("unregistered advertiser key accepted", e)
	}
	if before != d.configBytes(d.owner) {
		t.Fatal("invalid advertiser changed config")
	}

	for _, bindings := range []any{[]any{map[string]any{"kind": "identity", "id": "agent:x", "access": "read"}}, []space.Binding{{Kind: "project", ID: "z"}, {Kind: "identity", ID: "a"}}, []space.Binding{{Kind: "identity", ID: "a"}, {Kind: "identity", ID: "a"}}} {
		out := filepath.Join(d.root, "bad-ad.json")
		m, _ := d.invoke(d.owner, 3, "directory", "advertise", "--space", "space:test", "--out", out, "--bindings", d.jsonFile(bindings))
		if errorCodeOf(m) != "invalid_bindings" {
			t.Fatal(m)
		}
		if _, e := os.Lstat(out); !os.IsNotExist(e) {
			t.Fatal("invalid bindings created output")
		}
	}
	out := filepath.Join(d.root, "good-ad.json")
	m, _ := d.invoke(d.owner, 0, "directory", "advertise", "--space", "space:test", "--out", out, "--bindings", d.jsonFile([]space.Binding{{Kind: "identity", ID: "agent:x"}, {Kind: "project", ID: "project:y"}}))
	if !strings.Contains(stringMustJSON(t, m), "agent:x") {
		t.Fatal(m)
	}
	d.invoke(d.owner, 0, "directory", "publish", "--space", d.platform, "--entry", out)
	d.invoke(d.reader, 0, "directory", "show", "--space", d.platform, "--space-id", "space:test")
	m, _ = d.invoke(d.reader, 3, "directory", "advertise", "--space", d.platform, "--out", filepath.Join(d.root, "non-owner.json"))
	expectDirectoryCode(t, m, "directory_unauthorized")
}
func stringMustJSON(t *testing.T, v any) string {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return string(b)
}

// Two genuine Git branches publish competing v2 files. Merge arrival cannot
// replace the first-parent winner; the conflict remains diagnosed, not applied.
func TestDirectoryFirstParentFork(t *testing.T) {
	t.Parallel()
	d := newDirectory(t)
	ad := d.ad(d.owner, "space:test")
	d.publish(ad)
	item, e := d.localRepo(d.owner, d.platform).Directory("agent:owner")
	if e != nil {
		t.Fatal(e)
	}
	first := item[0].Entry
	fork := first
	fork.Version = 2
	prev := space.DirectoryDigest(first)
	fork.Previous = &prev
	forkAd := ad.Advertisement
	forkAd.Bindings = []space.Binding{{Kind: "project", ID: "project:competing"}}
	nested := d.resign(forkAd, d.localKey(d.owner))
	fork.Advertisement = &nested
	c, e := space.NewCanonicalDirectory(fork)
	if e != nil {
		t.Fatal(e)
	}
	sig, e := d.localKey(d.owner).SignDirectory(c)
	if e != nil {
		t.Fatal(e)
	}
	signed := space.SignedDirectory{Entry: fork, Signature: sig}
	branch := filepath.Join(d.root, "fork")
	d.git(d.root, "clone", "--no-tags", "--branch", "main", "--", d.platformRemote, branch)
	d.git(branch, "switch", "-c", "competing")
	path := space.DirectoryPath(fork)
	file := filepath.Join(branch, path)
	if e = os.MkdirAll(filepath.Dir(file), 0755); e != nil {
		t.Fatal(e)
	}
	b, _ := json.Marshal(signed)
	if e = os.WriteFile(file, b, 0644); e != nil {
		t.Fatal(e)
	}
	d.git(branch, "add", "--", path)
	d.git(branch, "commit", "-S", "-m", "competing directory version")
	d.publish(ad)
	items, e := d.localRepo(d.owner, d.platform).Directory("agent:owner")
	if e != nil {
		t.Fatal(e)
	}
	winner := items[0].Digest
	s, _ := selectSpace(d.config(d.owner), d.platform)
	d.git(s.ClonePath, "fetch", "--", branch, "competing")
	merge := exec.Command("git", "merge", "--no-ff", "--no-commit", "FETCH_HEAD")
	merge.Dir = s.ClonePath
	merge.Env = d.env
	output, err := merge.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "CONFLICT") {
		t.Fatal("missing intended merge conflict", err, string(output))
	}
	// Resolve the transport conflict to the competing bytes: replay must keep its
	// authenticated first-parent winner regardless of the final tree contents.
	if e = os.WriteFile(filepath.Join(s.ClonePath, path), b, 0644); e != nil {
		t.Fatal(e)
	}
	d.git(s.ClonePath, "add", "--", path)
	d.git(s.ClonePath, "commit", "-S", "-m", "merge competing directory bytes")
	d.git(s.ClonePath, "push", "origin", "HEAD:main")
	before := d.configBytes(d.reader)
	m, raw := d.invoke(d.reader, 0, "directory", "show", "--space", d.platform, "--space-id", "space:test")
	if !strings.Contains(raw, `"code":"directory_sequence"`) || !strings.Contains(raw, `"code":"directory_rewritten"`) {
		t.Fatal(raw)
	}
	data := agentprofile.Object(agentprofile.Object(m["data"])["entry"])
	if data["digest"] != winner {
		t.Fatal("competing branch replaced first-parent winner", raw)
	}
	d.unchangedConfig(before)
	d.addTarget(0)
}

// A batch introduced at one first-parent position replays canonical decimal
// versions numerically (including 10+); invalid paths/chains cannot hide v12.
func TestDirectoryBatchVersions(t *testing.T) {
	t.Parallel()
	d := newDirectory(t)
	d.publish(d.ad(d.owner, "space:test"))
	before := d.configBytes(d.reader)
	first := d.forgedEntry("space:batch", d.localKey(d.owner))
	files := map[string]any{}
	previous := ""
	for version := int64(1); version <= 12; version++ {
		entry := first.Entry
		entry.Version = version
		if version > 1 {
			p := previous
			entry.Previous = &p
		}
		c, e := space.NewCanonicalDirectory(entry)
		if e != nil {
			t.Fatal(e)
		}
		sig, e := d.localKey(d.owner).SignDirectory(c)
		if e != nil {
			t.Fatal(e)
		}
		files[space.DirectoryPath(entry)] = space.SignedDirectory{Entry: entry, Signature: sig}
		previous = space.DirectoryDigest(entry)
	}
	files[strings.TrimSuffix(space.DirectoryPath(first.Entry), "1.json")+"01.json"] = first
	d.plant(files, "")
	m, raw := d.invoke(d.reader, 0, "directory", "show", "--space", d.platform, "--space-id", "space:batch")
	entry := agentprofile.Object(agentprofile.Object(agentprofile.Object(m["data"])["entry"])["entry"])
	if entry["version"] != int64(12) || !strings.Contains(raw, `"code":"directory_path_mismatch"`) {
		t.Fatal(raw)
	}
	d.unchangedConfig(before)
	d.addTarget(0)
}

// Even a caller-configured, explicitly enabled ext helper selected by insteadOf
// cannot execute during discovery clone or later target sync. A direct fixture
// control first proves the marker detects this exact helper execution.
func TestDirectoryTransportRewrite(t *testing.T) {
	t.Parallel()
	d := newDirectory(t)
	marker := filepath.Join(d.root, "helper-called")
	helper := filepath.Join(d.root, "fixture-helper")
	if e := os.WriteFile(helper, []byte("#!/bin/sh\nprintf called > \"$DIRECTORY_HELPER_MARKER\"\nexit 1\n"), 0700); e != nil {
		t.Fatal(e)
	}
	configuration := filepath.Join(d.root, "rewrite.config")
	alias := "https://example.invalid/discovery"
	d.git(d.root, "config", "--file", configuration, "protocol.ext.allow", "always")
	d.git(d.root, "config", "--file", configuration, "url.ext::"+helper+".insteadOf", alias)
	original := append([]string{}, d.env...)
	filtered := []string{}
	for _, entry := range d.env {
		if !strings.HasPrefix(entry, "GIT_ALLOW_PROTOCOL=") && !strings.HasPrefix(entry, "GIT_CONFIG_GLOBAL=") {
			filtered = append(filtered, entry)
		}
	}
	d.env = append(filtered, "GIT_CONFIG_GLOBAL="+configuration, "DIRECTORY_HELPER_MARKER="+marker)
	control := exec.Command("git", "ls-remote", "--", alias)
	control.Dir = d.root
	control.Env = d.env
	_, err := control.CombinedOutput()
	if err == nil {
		t.Fatal("fixture helper unexpectedly served git")
	}
	if _, e := os.Stat(marker); e != nil {
		t.Fatal("helper control did not execute", e)
	}
	if e := os.Remove(marker); e != nil {
		t.Fatal(e)
	}
	candidate := filepath.Join(d.root, "guarded-clone")
	err = space.CloneDirectory(context.Background(), space.Git{Directory: candidate, Environment: d.env}, alias, "main")
	if err == nil {
		t.Fatal("helper clone succeeded")
	}
	if _, e := os.Stat(marker); !os.IsNotExist(e) {
		t.Fatal("discovery clone executed helper")
	}
	// An already discovered file target is relocated by caller config to the
	// rewritten URL; subsequent sync must enforce the same transport allowlist.
	hostile := append([]string{}, d.env...)
	d.env = original
	d.publish(d.ad(d.owner, "space:test"))
	d.addTarget(0)
	s, _ := selectSpace(d.config(d.reader), "space:test")
	d.git(s.ClonePath, "remote", "set-url", "origin", alias)
	d.env = hostile
	before := d.configBytes(d.reader)
	m, _ := d.invoke(d.reader, 6, "sync", "--space", "space:test")
	expectDirectoryCode(t, m, "git_failed")
	d.unchangedConfig(before)
	if _, e := os.Stat(marker); !os.IsNotExist(e) {
		t.Fatal("discovered target sync executed helper")
	}
	d.env = original
	d.git(s.ClonePath, "remote", "set-url", "origin", d.remote)
	d.invoke(d.reader, 0, "sync", "--space", "space:test")
}

// A readable foreign platform cannot become the caller's discovery root. Its
// namespace comes from genesis owners even when its space name has no prefix.
func TestDirectoryOwnPlatformRestriction(t *testing.T) {
	t.Parallel()
	h := newCLI(t)
	a := filepath.Join(h.root, "a")
	b := filepath.Join(h.root, "b")
	m, _ := h.invoke(a, 0, "keys", "init", "--identity", "a/agent:owner")
	public := agentprofile.Object(m["data"])["public_key"].(string)
	h.invoke(b, 0, "keys", "init", "--identity", "b/agent:owner")
	pins := map[string]string{}
	remotes := map[string]string{}
	for _, pair := range [][2]string{{a, "space:own-platform"}, {b, "space:foreign-platform"}} {
		remote := filepath.Join(h.root, pair[1]+".git")
		h.git(h.root, "init", "--bare", "--initial-branch=main", remote)
		m, _ := h.invoke(pair[0], 0, "spaces", "init", pair[1], "--remote", remote, "--kind", "platform")
		pins[pair[1]] = agentprofile.Object(m["data"])["policy_digest"].(string)
		remotes[pair[1]] = remote
	}
	h.invoke(b, 0, "keys", "register", "--space", "space:foreign-platform", "--identity", "a/agent:owner", "--public-key", public)
	h.invoke(b, 0, "policy", "grant", "--space", "space:foreign-platform", "--identity", "a/agent:owner", "--role", "reader")
	h.invoke(a, 0, "spaces", "add", "space:foreign-platform", "--remote", remotes["space:foreign-platform"], "--genesis", pins["space:foreign-platform"], "--kind", "platform")
	h.invoke(a, 0, "recall", "*", "--space", "space:foreign-platform")
	before := h.configBytes(a)
	m, _ = h.invoke(a, 3, "spaces", "add", "space:absent", "--from-directory", "space:foreign-platform")
	expectDirectoryCode(t, m, "identity_owner_mismatch")
	if before != h.configBytes(a) {
		t.Fatal("foreign directory changed config")
	}
	h.invoke(a, 0, "directory", "list", "--space", "space:own-platform")
}
