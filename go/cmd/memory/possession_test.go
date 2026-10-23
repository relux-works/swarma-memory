package main

import (
	"bytes"
	"encoding/base64"
	wire "encoding/binary"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/relux-works/swarma-memory/go/agentprofile"
	"github.com/relux-works/swarma-memory/go/kernel"
	"github.com/relux-works/swarma-memory/go/sign"
)

// Rebuild the reviewer's public-only endpoint without the candidate agent,
// encoder or any signing implementation. Listing an owner's public bytes is
// possible for an attacker; neither a listing nor a fabricated 64-byte response
// may establish a named reader or owner. The fixture owns and joins its listener.
func publicOnlyEndpoint(t *testing.T, public []byte, mode string) (string, string, func()) {
	t.Helper()
	str := func(b []byte) []byte { return append(wire.BigEndian.AppendUint32(nil, uint32(len(b))), b...) }
	blob := append(str([]byte("ssh-ed25519")), str(public)...)
	dir, e := os.MkdirTemp("", "po-")
	if e != nil {
		t.Fatal(e)
	}
	socket := filepath.Join(dir, "s")
	l, e := net.Listen("unix", socket)
	if e != nil {
		os.RemoveAll(dir)
		t.Fatal(e)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				var header [4]byte
				if _, e := io.ReadFull(c, header[:]); e != nil {
					return
				}
				n := wire.BigEndian.Uint32(header[:])
				if n < 1 || n > 256*1024-4 {
					return
				}
				request := make([]byte, int(n))
				if _, e := io.ReadFull(c, request); e != nil {
					return
				}
				response := []byte{5}
				if len(request) == 1 && request[0] == 11 {
					response = append([]byte{12, 0, 0, 0, 1}, append(str(blob), str(nil)...)...)
				} else if request[0] == 13 && mode == "invalid" {
					response = append([]byte{14}, str(append(str([]byte("ssh-ed25519")), str(make([]byte, 64))...))...)
				}
				_, _ = c.Write(append(wire.BigEndian.AppendUint32(nil, uint32(len(response))), response...))
			}()
		}
	}()
	var once sync.Once
	stop := func() { once.Do(func() { l.Close(); <-done; os.RemoveAll(dir) }) }
	t.Cleanup(func() {
		stop()
		if c, e := net.DialTimeout("unix", socket, 50*time.Millisecond); e == nil {
			c.Close()
			t.Error("public-only endpoint survived cleanup")
		}
	})
	return socket, "ssh-ed25519 " + base64.StdEncoding.EncodeToString(blob), stop
}

// Capture both output streams so a correct JSON refusal cannot conceal protected
// data in stderr. Process environment is the same isolated fixture as the CLI.
func possessionRefusal(t *testing.T, h *cliHarness, home string, args ...string) (map[string]any, string) {
	t.Helper()
	cmd := exec.Command(binary, append([]string{"--home", home, "--json"}, args...)...)
	cmd.Env, cmd.Dir = h.env, h.root
	var out, errout bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errout
	if e := cmd.Run(); e == nil || cmd.ProcessState == nil || cmd.ProcessState.ExitCode() != 3 {
		t.Fatal("expected authentication refusal", e, out.String(), errout.String())
	}
	v, refusal := kernel.DecodeJSON(out.Bytes())
	m := agentprofile.Object(v)
	if refusal != nil || len(m) != 5 || m["type"] != "error" || m["data_classification"] != "data" || m["data"] != nil || agentprofile.Object(m["error"])["exit"] != int64(3) {
		t.Fatal("invalid refusal envelope", out.String())
	}
	return m, errout.String()
}

// This is the independent review witness, expanded to all four requested reads,
// conflicts and owner administration. No owner's private key reaches the peer.
// Every failure has null data and preserves config, policy and publication state;
// localfile and a genuine registered agent positively retrieve the same witness.
func TestSSHAgentPublicOnlyImpersonation(t *testing.T) {
	t.Parallel()
	h := newCLI(t)
	h.add(h.owner, "record:private", "private owner witness")
	h.invoke(h.owner, 0, "policy", "resolvers", "set", "--space", "space:test", "--area", "owner-route", "--identities", `["agent:owner"]`)
	shown, _ := h.invoke(h.owner, 0, "keys", "show")
	pub, e := base64.StdEncoding.DecodeString(agentprofile.Object(shown["data"])["public_key"].(string))
	if e != nil {
		t.Fatal(e)
	}
	commands := [][]string{
		{"recall", "*", "--space", "space:test"}, {"explain", "record:private", "--space", "space:test"},
		{"changes", "--space", "space:test"}, {"policy", "resolvers", "show", "--space", "space:test"},
		{"conflicts", "--space", "space:test", "--id", "record:private"},
		{"conflicts", "--ref", "space:test:record:private:1"},
		{"policy", "grant", "--space", "space:test", "--identity", "reader:forged", "--role", "reader"},
	}
	for _, tc := range []struct{ mode, code string }{{"offline", "signer_unavailable"}, {"listing-only", "signer_refused"}, {"invalid", "invalid_signature"}} {
		t.Run(tc.mode, func(t *testing.T) {
			local := *h
			local.t = t
			socket, line, stop := publicOnlyEndpoint(t, pub, tc.mode)
			home := agentHome(t, &local, "impostor-"+tc.mode, "agent:owner", socket, line)
			if tc.mode == "offline" {
				stop()
			}
			local.invoke(home, 0, "spaces", "add", "space:test", "--remote", h.remote, "--genesis", h.pin)
			before := local.writeState(home)
			s, _ := selectSpace(local.config(home), "space:test")
			policy, _ := os.ReadFile(filepath.Join(s.ClonePath, "space.json"))
			for _, args := range commands {
				m, stderr := possessionRefusal(t, &local, home, args...)
				encoded := jsonBytesForTest(t, m)
				if errorCodeOf(m) != tc.code || m["data"] != nil || bytes.Contains(encoded, []byte("private owner witness")) || bytes.Contains(encoded, []byte("owner-route")) || strings.Contains(stderr, "private owner witness") || strings.Contains(stderr, "owner-route") {
					t.Fatal(args, m, stderr)
				}
				local.unchanged(home, before)
				after, _ := os.ReadFile(filepath.Join(s.ClonePath, "space.json"))
				if !bytes.Equal(policy, after) {
					t.Fatal("policy changed")
				}
			}
			local.invoke(home, 0, "keys", "show") // Public config stays offline.
		})
	}
	genuine := newCLIAgent(t)
	h.invoke(h.owner, 0, "keys", "register", "--space", "space:test", "--identity", "agent:owner", "--public-key", base64.StdEncoding.EncodeToString(genuine.public))
	home := agentHome(t, h, "genuine-owner", "agent:owner", genuine.socket, genuine.pubLine())
	h.invoke(home, 0, "spaces", "add", "space:test", "--remote", h.remote, "--genesis", h.pin)
	for _, owner := range []string{h.owner, home} {
		for _, args := range commands[:4] {
			m, _ := h.invoke(owner, 0, args...)
			if len(args) > 1 && args[0] == "policy" {
				if !bytes.Contains(jsonBytesForTest(t, m["data"]), []byte("owner-route")) {
					t.Fatal("missing genuine owner control")
				}
			} else if !bytes.Contains(jsonBytesForTest(t, m["data"]), []byte("private owner witness")) {
				t.Fatal("missing genuine reader control", args)
			}
		}
	}
}

// Multiple protected spaces in one CLI invocation request exactly one proof.
// The next process requests a new proof; public-only grants and public metadata
// commands remain available without agent contact. Named readers never silently
// fall back to public after a failed proof.
func TestSSHAgentPossessionCommandScopeAndPublic(t *testing.T) {
	t.Parallel()
	f := newCLIAgent(t)
	h := newAgentCLI(t, f.socket, f.pubLine())
	h.add(h.owner, "record:one", "private one")
	remote := filepath.Join(h.root, "second.git")
	h.git(h.root, "init", "--bare", "--initial-branch=main", remote)
	h.invoke(h.owner, 0, "spaces", "init", "space:second", "--remote", remote)
	count := func() int { f.mu.Lock(); defer f.mu.Unlock(); return f.purposes[sign.PossessionPurpose] }
	before := count()
	for i := 1; i <= 2; i++ {
		h.invoke(h.owner, 0, "recall", "*")
		if count() != before+i {
			t.Fatal("proof not scoped to one command", count()-before)
		}
	}
	f.set("missing")
	m, _ := h.invoke(h.owner, 3, "recall", "*", "--space", "space:test")
	if errorCodeOf(m) != "signer_key_missing" || m["data"] != nil {
		t.Fatal(m)
	}
	f.set("")
	h.invoke(h.owner, 0, "recall", "*", "--space", "space:test")
	h.invoke(h.owner, 0, "policy", "grant", "--space", "space:test", "--identity", "public", "--role", "reader")
	before = count()
	f.set("refused")
	m, _ = h.invoke(h.owner, 3, "recall", "*", "--space", "space:test")
	if errorCodeOf(m) != "signer_refused" || m["data"] != nil || count() != before+1 {
		t.Fatal("named reader fell back to public", m)
	}
	f.set("")
	publicHome := agentHome(t, h, "public-reader", "reader:unregistered", f.socket, f.pubLine())
	h.invoke(publicHome, 0, "spaces", "add", "space:test", "--remote", h.remote, "--genesis", h.pin)
	f.set("refused")
	parked := f.socket + ".parked"
	if e := os.Rename(f.socket, parked); e != nil {
		t.Fatal(e)
	}
	defer func() {
		if e := os.Rename(parked, f.socket); e != nil {
			t.Error(e)
		}
	}()
	before = count()
	for _, args := range [][]string{{"keys", "show"}, {"spaces", "list"}, {"spaces", "show", "space:test"}, {"sync", "--space", "space:test"}, {"check", "--space", "space:test"}, {"recall", "*", "--space", "space:test"}, {"explain", "record:one", "--space", "space:test"}, {"changes", "--space", "space:test"}} {
		h.invoke(publicHome, 0, args...)
	}
	h.invoke(publicHome, 0, "conflicts", "--space", "space:test", "--id", "record:one")
	h.invoke(publicHome, 7, "conflicts", "--ref", "space:test:record:one:1")
	if count() != before {
		t.Fatal("public path challenged")
	}
}

// Discovery, directory reads/diagnostics and promotion all cross the same
// possession boundary. Refusal must escape even sync/check's optional diagnostic
// path with null data. Genuine retries succeed; promotion authenticates once
// despite also reading a source principal and producing stored signatures.
func TestSSHAgentPossessionDirectoryAndPromotion(t *testing.T) {
	t.Parallel()
	f := newCLIAgent(t)
	h := newAgentCLI(t, f.socket, f.pubLine())
	h.add(h.owner, "record:source", "source witness")
	remote := filepath.Join(h.root, "platform.git")
	h.git(h.root, "init", "--bare", "--initial-branch=main", remote)
	m, _ := h.invoke(h.owner, 0, "spaces", "init", "space:platform", "--remote", remote, "--kind", "platform")
	pin := agentprofile.Object(m["data"])["policy_digest"].(string)
	ad := filepath.Join(h.root, "ad.json")
	h.invoke(h.owner, 0, "directory", "advertise", "--space", "space:test", "--out", ad)
	h.invoke(h.owner, 0, "directory", "publish", "--space", "space:platform", "--entry", ad)
	discovery := agentHome(t, h, "discovery", "agent:owner", f.socket, f.pubLine())
	h.invoke(discovery, 0, "spaces", "add", "space:platform", "--remote", remote, "--genesis", pin, "--kind", "platform")
	f.set("refused")
	m, _ = h.invoke(discovery, 3, "spaces", "add", "space:test", "--from-directory", "space:platform")
	if errorCodeOf(m) != "signer_refused" || m["data"] != nil || len(h.config(discovery).Spaces) != 1 {
		t.Fatal("discovery proceeded without proof", m)
	}
	f.set("")
	h.invoke(discovery, 0, "spaces", "add", "space:test", "--from-directory", "space:platform")
	for _, args := range [][]string{
		{"directory", "list", "--space", "space:platform"},
		{"directory", "show", "--space", "space:platform", "--space-id", "space:test"},
		{"spaces", "update", "space:test", "--from-directory", "space:platform"},
		{"sync", "--space", "space:test"}, {"check", "--space", "space:test"},
	} {
		before := h.configBytes(discovery)
		f.set("refused")
		m, _ = h.invoke(discovery, 3, args...)
		if errorCodeOf(m) != "signer_refused" || m["data"] != nil || h.configBytes(discovery) != before {
			t.Fatal(args, m)
		}
		f.set("")
		h.invoke(discovery, 0, args...)
	}
	args := []string{"promote", "record:source", "--space", "space:test", "--to", "space:platform", "--id", "record:promoted", "--idempotency-key", "proof:promote"}
	before := h.writeState(h.owner)
	f.set("refused")
	m, _ = h.invoke(h.owner, 3, args...)
	if errorCodeOf(m) != "signer_refused" || m["data"] != nil {
		t.Fatal(m)
	}
	h.unchanged(h.owner, before)
	f.set("")
	f.mu.Lock()
	count := f.purposes[sign.PossessionPurpose]
	f.mu.Unlock()
	h.invoke(h.owner, 0, args...)
	f.mu.Lock()
	after := f.purposes[sign.PossessionPurpose]
	f.mu.Unlock()
	if after != count+1 {
		t.Fatal("promotion challenged more than once")
	}
	// The same directory/discovery paths use public grants with no endpoint.
	h.invoke(h.owner, 0, "policy", "grant", "--space", "space:platform", "--identity", "public", "--role", "reader")
	public := agentHome(t, h, "public-directory", "reader:unregistered", f.socket, f.pubLine())
	h.invoke(public, 0, "spaces", "add", "space:platform", "--remote", remote, "--genesis", pin, "--kind", "platform")
	parked := f.socket + ".parked"
	if e := os.Rename(f.socket, parked); e != nil {
		t.Fatal(e)
	}
	defer func() {
		if e := os.Rename(parked, f.socket); e != nil {
			t.Error(e)
		}
	}()
	for _, args := range [][]string{
		{"directory", "list", "--space", "space:platform"},
		{"directory", "show", "--space", "space:platform", "--space-id", "space:test"},
		{"spaces", "add", "space:test", "--from-directory", "space:platform"},
		{"spaces", "update", "space:test", "--from-directory", "space:platform"},
		{"sync", "--space", "space:test"}, {"check", "--space", "space:test"},
	} {
		h.invoke(public, 0, args...)
	}
}
