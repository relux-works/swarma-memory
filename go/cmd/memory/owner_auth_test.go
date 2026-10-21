package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/relux-works/swarma-memory/go/agentprofile"
)

// Every resolver action authenticates the owner's registered key, not just its
// claimed name. Refusals disclose no administrative data and preserve verified
// clone/config/remote state; genuine-owner set/show/remove remain usable.
func TestResolverActionsRequireRegisteredOwnerKey(t *testing.T) {
	h := newCLI(t)
	h.connectReader()
	set := []string{"policy", "resolvers", "set", "--space", "space:test", "--area", "known", "--identities", `["agent:owner"]`}
	show := []string{"policy", "resolvers", "show", "--space", "space:test"}
	remove := []string{"policy", "resolvers", "remove", "--space", "space:test", "--area", "known"}
	h.invoke(h.owner, 0, set...)
	m, _ := h.invoke(h.owner, 0, show...)
	if len(agentprofile.Array(agentprofile.Object(m["data"])["resolvers"])) != 1 {
		t.Fatal("genuine owner did not see populated route", m)
	}
	registeredMismatch := filepath.Join(h.root, "registered-mismatch")
	m, _ = h.invoke(registeredMismatch, 0, "keys", "init", "--identity", "agent:owner")
	// Register this key to another identity: key membership alone is insufficient.
	h.invoke(h.owner, 0, "keys", "register", "--space", "space:test", "--identity", "agent:other", "--public-key", agentprofile.Object(m["data"])["public_key"].(string))
	unregisteredOwner := filepath.Join(h.root, "unregistered-owner")
	h.invoke(unregisteredOwner, 0, "keys", "init", "--identity", "agent:owner")
	unknown := filepath.Join(h.root, "unknown")
	h.invoke(unknown, 0, "keys", "init", "--identity", "agent:unknown")
	for _, home := range []string{registeredMismatch, unregisteredOwner, unknown} {
		h.invoke(home, 0, "spaces", "add", "space:test", "--remote", h.remote, "--genesis", h.pin, "--kind", "project")
	}
	for _, caller := range []struct{ name, home, code string }{
		{"registered-key-wrong-identity", registeredMismatch, "unregistered_key"},
		{"unregistered-owner-key", unregisteredOwner, "unregistered_key"},
		{"unknown-identity", unknown, "unauthorized_owner"},
		{"registered-non-owner", h.reader, "unauthorized_owner"},
	} {
		t.Run(caller.name, func(t *testing.T) {
			h := *h
			h.t = t
			h.localRepo(caller.home, "space:test") // Establish the current verified cursor before snapshots.
			for _, args := range [][]string{show, set, remove} {
				before := h.writeState(caller.home)
				m, _ := h.invoke(caller.home, 3, args...)
				if errorCodeOf(m) != caller.code || m["data"] != nil {
					t.Fatal("owner authentication did not fail closed", m)
				}
				h.unchanged(caller.home, before)
			}
		})
	}
	h.invoke(h.owner, 0, remove...)
	m, _ = h.invoke(h.owner, 0, show...)
	if len(agentprofile.Array(agentprofile.Object(m["data"])["resolvers"])) != 0 {
		t.Fatal("genuine owner could not remove route", m)
	}
}

// Other owner commands already verify signatures against the preceding/current
// policy before publishing. A fresh same-name key cannot self-register, alter
// grants, export an advertisement, publish or withdraw; genuine-owner controls
// exercise each operation. No refused command creates output or changes state.
func TestOwnerCommandKeyAuthenticationAudit(t *testing.T) {
	d := newDirectory(t)
	impostor := filepath.Join(d.root, "impostor")
	m, _ := d.invoke(impostor, 0, "keys", "init", "--identity", "agent:owner")
	public := agentprofile.Object(m["data"])["public_key"].(string)
	d.invoke(impostor, 0, "spaces", "add", "space:test", "--remote", d.remote, "--genesis", d.pin, "--kind", "project")
	d.pinPlatform(impostor)
	adFile := filepath.Join(d.root, "owner-ad.json")
	d.invoke(d.owner, 0, "directory", "advertise", "--space", "space:test", "--out", adFile)
	d.invoke(d.owner, 0, "directory", "publish", "--space", d.platform, "--entry", adFile)
	badOutput := filepath.Join(d.root, "impostor-ad.json")
	for _, probe := range []struct {
		name, space, code string
		args              []string
	}{
		{"self-register", "space:test", "unregistered_key", []string{"keys", "register", "--space", "space:test", "--identity", "agent:owner", "--public-key", public}},
		{"grant-reader", "space:test", "unregistered_key", []string{"policy", "grant", "--space", "space:test", "--identity", "agent:unknown", "--role", "reader"}},
		{"revoke-reader", "space:test", "unregistered_key", []string{"policy", "revoke", "--space", "space:test", "--identity", "agent:owner", "--role", "reader"}},
		{"grant-writer", "space:test", "unregistered_key", []string{"policy", "grant", "--space", "space:test", "--identity", "agent:unknown", "--role", "writer"}},
		{"revoke-writer", "space:test", "unregistered_key", []string{"policy", "revoke", "--space", "space:test", "--identity", "agent:owner", "--role", "writer"}},
		{"advertise", "space:test", "directory_unauthorized", []string{"directory", "advertise", "--space", "space:test", "--out", badOutput}},
		{"publish", d.platform, "directory_unauthorized", []string{"directory", "publish", "--space", d.platform, "--entry", adFile}},
		{"withdraw", d.platform, "directory_unauthorized", []string{"directory", "withdraw", "--space", d.platform, "--space-id", "space:test"}},
	} {
		t.Run(probe.name, func(t *testing.T) {
			h := *d.cliHarness
			h.t = t
			h.localRepo(impostor, probe.space)
			before := h.stateIn(impostor, probe.space)
			m, _ := h.invoke(impostor, 3, probe.args...)
			if errorCodeOf(m) != probe.code || m["data"] != nil {
				t.Fatal("owner-command authentication did not fail closed", m)
			}
			if after := h.stateIn(impostor, probe.space); after != before {
				t.Fatal("refused command changed state", before, after)
			}
			if _, e := os.Lstat(badOutput); !os.IsNotExist(e) {
				t.Fatal("refused advertisement created output", e)
			}
		})
	}
	// Use the same registration/grant intents with the genuine owner as control.
	d.invoke(d.owner, 0, "keys", "register", "--space", "space:test", "--identity", "agent:unknown", "--public-key", public)
	for _, role := range []string{"reader", "writer"} {
		d.invoke(d.owner, 0, "policy", "grant", "--space", "space:test", "--identity", "agent:unknown", "--role", role)
		d.invoke(d.owner, 0, "policy", "revoke", "--space", "space:test", "--identity", "agent:unknown", "--role", role)
	}
	d.invoke(d.owner, 0, "directory", "withdraw", "--space", d.platform, "--space-id", "space:test")
}
