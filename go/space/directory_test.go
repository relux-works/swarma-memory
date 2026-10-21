package space_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/swarma-memory/go/sign"
	"github.com/relux-works/swarma-memory/go/space"
)

// Invalid helper/option locations cannot start Git; an allowed HTTPS control
// does start the deliberately failing fixture executable (never a real server).
func TestDirectoryTransportBeforeGit(t *testing.T) {
	root := t.TempDir()
	marker := filepath.Join(root, "called")
	git := filepath.Join(root, "git")
	if e := os.WriteFile(git, []byte("#!/bin/sh\nprintf called > \"$DIRECTORY_TEST_MARKER\"\nexit 1\n"), 0700); e != nil {
		t.Fatal(e)
	}
	for _, remote := range []string{"ssh://git@example.invalid/repo", "ssh://git@[2001:db8::1]/repo", "git@example.invalid:repo", "https://example.invalid/repo"} {
		if e := space.DirectoryRemote(remote, []string{"GIT_ALLOW_PROTOCOL=ssh:https"}); e != nil {
			t.Fatal(remote, e)
		}
	}
	t.Setenv("PATH", root)
	env := []string{"PATH=" + root, "DIRECTORY_TEST_MARKER=" + marker}
	for _, remote := range []string{"ext::sh -c false", "-option", "https://example.invalid/path\nnext", "git-remote::payload", "file:///unapproved"} {
		e := space.CloneDirectory(context.Background(), space.Git{Directory: filepath.Join(root, "clone"), Environment: env}, remote, "main")
		if e == nil || e.Error() != "directory_transport" {
			t.Fatal(remote, e)
		}
		if _, e := os.Stat(marker); !os.IsNotExist(e) {
			t.Fatal("refused remote started git")
		}
	}
	e := space.CloneDirectory(context.Background(), space.Git{Directory: filepath.Join(root, "clone"), Environment: env}, "https://example.invalid/repo", "main")
	if e == nil {
		t.Fatal("fake git unexpectedly succeeded")
	}
	if _, e := os.Stat(marker); e != nil {
		t.Fatal("positive control did not start git")
	}
}

// Namespace checks use genesis owners, retain that anchor through transitions,
// accept foreign registered readers, and reject mixed owners and foreign writes.
func TestDirectoryPolicyNamespaces(t *testing.T) {
	f := newFixture(t)
	owner := key(t, "a/agent:owner")
	foreign := key(t, "b/agent:reader")
	p := clone(t, f.policy.Policy)
	p.Owners = []string{owner.Identity()}
	p.Author = owner.Identity()
	p.Keys = []space.SignedRegistration{registration(t, owner, owner, p.SpaceID, 1), registration(t, owner, foreign, p.SpaceID, 1)}
	p.Writers = []space.Writer{}
	p.Readers = []space.Reader{{Identity: foreign.Identity(), Spaces: []string{}}}
	p.Resolvers = []space.Resolver{}
	signed := signPolicy(t, owner, p)
	c, e := space.NewCanonicalPolicy(p)
	check(t, e)
	pin := sign.PolicyDigest(c.Bytes())
	chain, e := space.VerifyChain([]space.SignedPolicy{signed}, pin)
	check(t, e)
	if chain[0].OwnerNamespace() != "a" {
		t.Fatal("namespace came from space id")
	}
	for _, tc := range []struct {
		name, want string
		change     func(*space.Policy)
	}{
		{"mixed", "mixed_owner_namespace", func(p *space.Policy) { p.Owners = append(p.Owners, foreign.Identity()) }},
		{"unqualified-key", "identity_owner_mismatch", func(p *space.Policy) {
			k := key(t, "agent:bare")
			p.Keys = append(p.Keys, registration(t, owner, k, p.SpaceID, 1))
		}},
		{"unqualified-reader", "identity_owner_mismatch", func(p *space.Policy) {
			p.Readers = append(p.Readers, space.Reader{Identity: "agent:bare", Spaces: []string{}})
		}},
		{"foreign-writer", "cross_owner_writer", func(p *space.Policy) {
			w := clone(t, f.policy.Policy.Writers[0])
			w.Identity = foreign.Identity()
			p.Writers = append(p.Writers, w)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := clone(t, p)
			tc.change(&bad)
			s := signPolicy(t, owner, bad)
			c, e := space.NewCanonicalPolicy(bad)
			check(t, e)
			_, e = space.VerifyChain([]space.SignedPolicy{s}, sign.PolicyDigest(c.Bytes()))
			if e == nil || e.Error() != tc.want {
				t.Fatal(e, tc.want)
			}
		})
	}
	// A transition cannot replace the genesis namespace even with all new keys.
	next := clone(t, p)
	next.Version = 2
	next.Previous = &pin
	next.Owners = []string{foreign.Identity()}
	next.Keys = []space.SignedRegistration{{Registration: space.Registration{Identity: foreign.Identity(), Key: foreign.ID(), Alg: "ed25519", PublicKey: base64.StdEncoding.EncodeToString(foreign.PublicKey())}}}
	endorsed, e := space.EndorsePolicy(next, owner)
	check(t, e)
	_, e = space.VerifyChain([]space.SignedPolicy{signed, endorsed}, pin)
	if e == nil || !strings.Contains(e.Error(), "mixed_owner_namespace") {
		t.Fatal(e)
	}
}

// Closed directory objects preserve canonical bytes, reject unknown fields and
// swapped purposes, and local signers cannot attest another author's payload.
func TestDirectoryCanonicalBoundaries(t *testing.T) {
	f := newFixture(t)
	ad := space.Advertisement{Format: sign.AdvertisementPurpose, SpaceID: f.policy.Policy.SpaceID, Kind: f.policy.Policy.Kind, Bindings: []space.Binding{}, Git: space.Location{Remote: "ssh://git@example.invalid/repo", Branch: "main"}, GenesisDigest: f.anchor, ObservedPolicy: space.PolicyPin{Version: 1, Digest: f.anchor}, Author: f.owner.Identity()}
	c, e := space.NewCanonicalAdvertisement(ad)
	check(t, e)
	original := string(c.Bytes())
	bytes := c.Bytes()
	bytes[0] = 'x'
	if string(c.Bytes()) != original {
		t.Fatal("aliased canonical advertisement")
	}
	_, e = f.writer.SignAdvertisement(c)
	diagnostic(t, e, sign.SubmitterMismatch)
	sig, e := f.owner.SignAdvertisement(c)
	check(t, e)
	check(t, (sign.Ed25519Verifier{}).Verify(sign.AdvertisementPurpose, c.Bytes(), sig, f.owner.PublicKey()))
	signed := space.SignedAdvertisement{Advertisement: ad, Signature: sig}
	wire, e := json.Marshal(signed)
	check(t, e)
	_, e = space.ParseAdvertisement(wire)
	check(t, e)
	entry := space.DirectoryEntry{Format: sign.DirectoryPurpose, DirectorySpace: "space:platform", SpaceID: ad.SpaceID, Version: 1, Status: "active", Advertisement: &signed, Author: f.owner.Identity()}
	request, e := space.NewCanonicalDirectory(entry)
	check(t, e)
	_, e = f.writer.SignDirectory(request)
	diagnostic(t, e, sign.SubmitterMismatch)
	directorySig, e := f.owner.SignDirectory(request)
	check(t, e)
	check(t, (sign.Ed25519Verifier{}).Verify(sign.DirectoryPurpose, request.Bytes(), directorySig, f.owner.PublicKey()))
	for _, object := range []any{signed, space.SignedDirectory{Entry: entry, Signature: directorySig}} {
		b, e := json.Marshal(object)
		check(t, e)
		var m map[string]any
		check(t, json.Unmarshal(b, &m))
		m["access"] = "read"
		b, e = json.Marshal(m)
		check(t, e)
		if _, ok := m["entry"]; ok {
			_, e = space.ParseDirectory(b)
		} else {
			_, e = space.ParseAdvertisement(b)
		}
		diagnostic(t, e, sign.InvalidShape)
	}
	signed.Signature.Purpose = sign.DirectoryPurpose
	wire, e = json.Marshal(signed)
	check(t, e)
	_, e = space.ParseAdvertisement(wire)
	diagnostic(t, e, sign.PurposeMismatch)
	directorySig.Purpose = sign.AdvertisementPurpose
	wire, e = json.Marshal(space.SignedDirectory{Entry: entry, Signature: directorySig})
	check(t, e)
	_, e = space.ParseDirectory(wire)
	diagnostic(t, e, sign.PurposeMismatch)
}

// The transport allowlist removes helpers without widening a stricter explicit
// caller restriction; duplicate protocol variables follow last-value semantics.
func TestDirectoryEnvironment(t *testing.T) {
	for _, tc := range []struct {
		in   []string
		want string
	}{
		{[]string{"HOME=fixture"}, "GIT_ALLOW_PROTOCOL=ssh:https"},
		{[]string{"GIT_ALLOW_PROTOCOL=file"}, "GIT_ALLOW_PROTOCOL=file"},
		{[]string{"GIT_ALLOW_PROTOCOL=ssh:ext:https"}, "GIT_ALLOW_PROTOCOL=ssh:https"},
		{[]string{"GIT_ALLOW_PROTOCOL="}, "GIT_ALLOW_PROTOCOL="},
		{[]string{"GIT_ALLOW_PROTOCOL=file", "GIT_ALLOW_PROTOCOL=https"}, "GIT_ALLOW_PROTOCOL=https"},
	} {
		out := space.DirectoryEnvironment(tc.in)
		if out[len(out)-1] != tc.want {
			t.Fatal(out, tc.want)
		}
	}
}
