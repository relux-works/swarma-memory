package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	wire "encoding/binary"
	"encoding/json"
	"errors"
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
	"github.com/relux-works/swarma-memory/go/sign/sshagent"
	"github.com/relux-works/swarma-memory/go/space"
)

// This fixture deliberately encodes the agent wire independently of production.
// All sockets/keys are ephemeral; cleanup waits for every accept/request goroutine.
type cliAgent struct {
	mu             sync.Mutex
	mode           string
	public         ed25519.PublicKey
	private, other ed25519.PrivateKey
	socket         string
	listener       net.Listener
	stop, done     chan struct{}
	wg             sync.WaitGroup
	purposes       map[string]int
}

func sshStrings(parts ...[]byte) []byte {
	var b []byte
	for _, p := range parts {
		b = wire.BigEndian.AppendUint32(b, uint32(len(p)))
		b = append(b, p...)
	}
	return b
}
func sshString(b *[]byte) ([]byte, bool) {
	if len(*b) < 4 {
		return nil, false
	}
	n := wire.BigEndian.Uint32(*b)
	*b = (*b)[4:]
	if uint64(n) > uint64(len(*b)) {
		return nil, false
	}
	v := (*b)[:int(n)]
	*b = (*b)[int(n):]
	return v, true
}
func (f *cliAgent) pubLine() string {
	return "ssh-ed25519 " + base64.StdEncoding.EncodeToString(sshStrings([]byte("ssh-ed25519"), f.public)) + " memory-test"
}
func newCLIAgent(t *testing.T) *cliAgent {
	t.Helper()
	dir, e := os.MkdirTemp("", "ca-")
	if e != nil {
		t.Fatal(e)
	}
	pub, private, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	_, other, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	f := &cliAgent{public: pub, private: private, other: other, socket: filepath.Join(dir, "s"), stop: make(chan struct{}), done: make(chan struct{}), purposes: map[string]int{}}
	f.listener, e = net.Listen("unix", f.socket)
	if e != nil {
		os.RemoveAll(dir)
		t.Fatal(e)
	}
	go func() {
		defer close(f.done)
		for {
			c, e := f.listener.Accept()
			if e != nil {
				return
			}
			f.wg.Add(1)
			go func() { defer f.wg.Done(); f.serve(c) }()
		}
	}()
	t.Cleanup(func() {
		close(f.stop)
		f.listener.Close()
		<-f.done
		f.wg.Wait()
		os.RemoveAll(dir)
		if c, e := net.DialTimeout("unix", f.socket, 50*time.Millisecond); e == nil {
			c.Close()
			t.Error("agent listener survived cleanup")
		}
	})
	return f
}
func (f *cliAgent) set(mode string) { f.mu.Lock(); f.mode = mode; f.mu.Unlock() }
func (f *cliAgent) serve(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	var header [4]byte
	if _, e := io.ReadFull(c, header[:]); e != nil {
		return
	}
	n := wire.BigEndian.Uint32(header[:])
	if n < 1 || n > 256*1024 {
		return
	}
	b := make([]byte, int(n))
	if _, e := io.ReadFull(c, b); e != nil {
		return
	}
	f.mu.Lock()
	mode := f.mode
	f.mu.Unlock()
	if mode == "hang" {
		<-f.stop
		return
	}
	var out []byte
	switch b[0] {
	case 11:
		keys := [][]byte{sshStrings([]byte("ssh-ed25519"), f.public)}
		if mode == "missing" {
			keys = nil
		}
		if mode == "different" {
			keys = [][]byte{sshStrings([]byte("ssh-ed25519"), f.other.Public().(ed25519.PublicKey))}
		}
		if mode == "invalid-key" {
			keys = [][]byte{sshStrings([]byte("ssh-rsa"), []byte{1})}
		}
		out = wire.BigEndian.AppendUint32([]byte{12}, uint32(len(keys)))
		for _, k := range keys {
			out = append(out, sshStrings(k, []byte("fixture"))...)
		}
	case 13:
		rest := b[1:]
		pub, ok := sshString(&rest)
		if !ok || !bytes.Equal(pub, sshStrings([]byte("ssh-ed25519"), f.public)) {
			return
		}
		framed, ok := sshString(&rest)
		if !ok || len(rest) != 4 || wire.BigEndian.Uint32(rest) != 0 {
			return
		}
		at := bytes.IndexByte(framed, 0)
		if at < 0 {
			return
		}
		f.mu.Lock()
		f.purposes[string(framed[:at])]++
		f.mu.Unlock()
		private := f.private
		if mode == "wrong-key" {
			private = f.other
		}
		typ := "ssh-ed25519"
		if mode == "invalid-type" {
			typ = "ssh-rsa"
		}
		out = append([]byte{14}, sshStrings(sshStrings([]byte(typ), ed25519.Sign(private, framed)))...)
		if mode == "trailing" {
			out = append(out, 0)
		}
		if mode == "refused" || mode == "write-refused" && string(framed[:at]) == sign.WritePurpose || mode == "policy-refused" && string(framed[:at]) == sign.PolicyPurpose {
			out = []byte{5}
		}
	default:
		return
	}
	if mode == "oversize" {
		_, _ = c.Write(wire.BigEndian.AppendUint32(nil, 256*1024+1))
		return
	}
	frame := wire.BigEndian.AppendUint32(nil, uint32(len(out)))
	frame = append(frame, out...)
	if mode == "truncated" {
		frame = frame[:len(frame)-1]
	}
	_, _ = c.Write(frame)
}
func agentHome(t *testing.T, h *cliHarness, name, identity, socket, line string) string {
	t.Helper()
	path := filepath.Join(h.root, name)
	h.invoke(path, 0, "keys", "init", "--identity", identity, "--ssh-agent", socket, "--public-key", line)
	if _, e := os.Lstat(filepath.Join(path, "localkey.json")); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("agent init wrote key file", e)
	}
	data, _ := h.invoke(path, 0, "keys", "show")
	d := agentprofile.Object(data["data"])
	if d["backend"] != "ssh-agent" || d["socket"] != socket || d["identity"] != identity {
		t.Fatal(d)
	}
	return path
}
func newAgentCLI(t *testing.T, socket, line string) *cliHarness {
	t.Helper()
	h := newCLI(t)
	h.owner = agentHome(t, h, "agent-owner", "agent:owner", socket, line)
	h.remote = filepath.Join(h.root, "agent-remote.git")
	h.git(h.root, "init", "--bare", "--initial-branch=main", h.remote)
	m, _ := h.invoke(h.owner, 0, "spaces", "init", "space:test", "--remote", h.remote, "--kind", "project")
	d := agentprofile.Object(m["data"])
	h.pin = d["policy_digest"].(string)
	h.genesis = d["cursor"].(string)
	return h
}

// All six signer interfaces run through real CLI subprocesses. A separate
// localfile reader verifies the policies, record/revision and directory entry;
// the verifier and signature format are the same as for file-backed homes.
func TestSSHAgentCLIFlow(t *testing.T) {
	t.Parallel()
	owner := newCLIAgent(t)
	h := newAgentCLI(t, owner.socket, owner.pubLine())
	writer := newCLIAgent(t)
	writerHome := agentHome(t, h, "writer", "agent:writer", writer.socket, writer.pubLine())
	agentOwnerFlow(t, h, writerHome)
	owner.mu.Lock()
	defer owner.mu.Unlock()
	for _, purpose := range []string{sign.PolicyPurpose, sign.RegistrationPurpose, sign.AdvertisementPurpose, sign.DirectoryPurpose} {
		if owner.purposes[purpose] == 0 {
			t.Fatal("owner purpose not exercised", purpose)
		}
	}
	writer.mu.Lock()
	defer writer.mu.Unlock()
	for _, purpose := range []string{sign.RecordPurpose, sign.WritePurpose} {
		if writer.purposes[purpose] == 0 {
			t.Fatal("writer purpose not exercised", purpose)
		}
	}
}
func agentOwnerFlow(t *testing.T, h *cliHarness, writerHome string) {
	t.Helper()
	key, _ := h.invoke(writerHome, 0, "keys", "show")
	h.invoke(h.owner, 0, "keys", "register", "--space", "space:test", "--identity", "agent:writer", "--public-key", agentprofile.Object(key["data"])["public_key"].(string))
	h.invoke(h.owner, 0, "policy", "grant", "--space", "space:test", "--identity", "agent:writer", "--role", "writer")
	h.invoke(h.owner, 0, "policy", "grant", "--space", "space:test", "--identity", "agent:writer", "--role", "reader")
	h.invoke(h.owner, 0, "policy", "resolvers", "set", "--space", "space:test", "--area", "known", "--identities", `["agent:owner"]`)
	h.invoke(writerHome, 0, "spaces", "add", "space:test", "--remote", h.remote, "--genesis", h.pin)
	h.add(writerHome, "record:agent", "agent original")
	h.invoke(writerHome, 0, "revise", "record:agent", "--space", "space:test", "--relation", "replace", "--content", "agent revision", "--idempotency-key", "agent:revise", "--expected-version", "1")
	h.connectReader()
	_, raw := h.invoke(h.reader, 0, "recall", "agent revision", "--space", "space:test")
	if !strings.Contains(raw, "agent revision") {
		t.Fatal(raw)
	}
	platformRemote := filepath.Join(h.root, "agent-platform.git")
	h.git(h.root, "init", "--bare", "--initial-branch=main", platformRemote)
	m, _ := h.invoke(h.owner, 0, "spaces", "init", "space:platform", "--remote", platformRemote, "--kind", "platform")
	pin := agentprofile.Object(m["data"])["policy_digest"].(string)
	reader, _ := h.invoke(h.reader, 0, "keys", "show")
	pub := agentprofile.Object(reader["data"])["public_key"].(string)
	h.invoke(h.owner, 0, "keys", "register", "--space", "space:platform", "--identity", "agent:reader", "--public-key", pub)
	h.invoke(h.owner, 0, "policy", "grant", "--space", "space:platform", "--identity", "agent:reader", "--role", "reader")
	file := filepath.Join(h.root, "agent-advertisement.json")
	h.invoke(h.owner, 0, "directory", "advertise", "--space", "space:test", "--out", file)
	h.invoke(h.owner, 0, "directory", "publish", "--space", "space:platform", "--entry", file)
	h.invoke(h.reader, 0, "spaces", "add", "space:platform", "--remote", platformRemote, "--genesis", pin, "--kind", "platform")
	_, raw = h.invoke(h.reader, 0, "directory", "list", "--space", "space:platform")
	if !strings.Contains(raw, "space:test") {
		t.Fatal(raw)
	}
	h.invoke(h.reader, 0, "check")
}

// Each signing refusal leaves remote refs, all/reflog commit counts, index,
// policy bytes and config untouched; the same command succeeds after repair.
// Possession normalizes malformed key/type/frame responses to invalid_signature.
// A dirty clone is refused without overwriting its pre-existing policy bytes.
func TestSSHAgentCLIRefusalsAndRetry(t *testing.T) {
	t.Parallel()
	f := newCLIAgent(t)
	h := newAgentCLI(t, f.socket, f.pubLine())
	s, _ := selectSpace(h.config(h.owner), "space:test")
	policy := filepath.Join(s.ClonePath, "space.json")
	for i, tc := range []struct{ mode, code string }{
		{"missing", "signer_key_missing"}, {"different", "signer_key_missing"}, {"refused", "signer_refused"},
		{"policy-refused", "signer_refused"}, {"wrong-key", "invalid_signature"}, {"invalid-type", "invalid_signature"}, {"invalid-key", "invalid_signature"},
		{"trailing", "invalid_signature"}, {"truncated", "signer_unavailable"}, {"oversize", "invalid_signature"},
	} {
		before := h.writeState(h.owner)
		original, e := os.ReadFile(policy)
		if e != nil {
			t.Fatal(e)
		}
		f.set(tc.mode)
		args := []string{"policy", "grant", "--space", "space:test", "--identity", "reader:" + strconv64(int64(i)), "--role", "reader"}
		m, _ := h.invoke(h.owner, 3, args...)
		if errorCodeOf(m) != tc.code {
			t.Fatal(tc.mode, m)
		}
		h.unchanged(h.owner, before)
		after, e := os.ReadFile(policy)
		if e != nil || !bytes.Equal(original, after) {
			t.Fatal("policy changed", e)
		}
		f.set("")
		h.invoke(h.owner, 0, args...)
	}
	// Missing/refused connection uses the configured endpoint only. Restoring the
	// same path and config permits a valid retry, with no ambient-agent fallback.
	before := h.writeState(h.owner)
	original, _ := os.ReadFile(policy)
	parked := f.socket + ".parked"
	if e := os.Rename(f.socket, parked); e != nil {
		t.Fatal(e)
	}
	args := []string{"policy", "grant", "--space", "space:test", "--identity", "reader:unavailable", "--role", "reader"}
	m, _ := h.invoke(h.owner, 3, args...)
	if errorCodeOf(m) != "signer_unavailable" {
		t.Fatal(m)
	}
	h.unchanged(h.owner, before)
	after, _ := os.ReadFile(policy)
	if !bytes.Equal(original, after) {
		t.Fatal("policy changed")
	}
	// A stale socket inode separately witnesses ECONNREFUSED rather than ENOENT.
	stale, e := net.Listen("unix", f.socket)
	if e != nil {
		t.Fatal(e)
	}
	stale.(*net.UnixListener).SetUnlinkOnClose(false)
	stale.Close()
	m, _ = h.invoke(h.owner, 3, args...)
	if errorCodeOf(m) != "signer_unavailable" {
		t.Fatal(m)
	}
	h.unchanged(h.owner, before)
	after, _ = os.ReadFile(policy)
	if !bytes.Equal(original, after) {
		t.Fatal("policy changed")
	}
	if e = os.Remove(f.socket); e != nil {
		t.Fatal(e)
	}
	if e = os.Rename(parked, f.socket); e != nil {
		t.Fatal(e)
	}
	h.invoke(h.owner, 0, args...)
	before = h.writeState(h.owner)
	original, _ = os.ReadFile(policy)
	dirty := append(append([]byte(nil), original...), []byte("\n dirty memory test\n")...)
	if e := os.WriteFile(policy, dirty, 0600); e != nil {
		t.Fatal(e)
	}
	m, _ = h.invoke(h.owner, 3, "policy", "grant", "--space", "space:test", "--identity", "reader:dirty", "--role", "reader")
	if errorCodeOf(m) != "dirty_clone" {
		t.Fatal(m)
	}
	after, _ = os.ReadFile(policy)
	if !bytes.Equal(after, dirty) || h.configBytes(h.owner) != before.config || h.git(h.remote, "rev-parse", "main") != before.remote {
		t.Fatal("dirty refusal overwrote state")
	}
	if e := os.WriteFile(policy, original, 0600); e != nil {
		t.Fatal(e)
	}
	h.unchanged(h.owner, before)
	h.invoke(h.owner, 0, "policy", "grant", "--space", "space:test", "--identity", "reader:dirty", "--role", "reader")
	// A transaction-signing failure after successful record signatures must not leave files or commits behind;
	// repairing the same agent permits the same valid write intent.
	before = h.writeState(h.owner)
	f.set("write-refused")
	m, _ = h.invoke(h.owner, 3, "add", "assertion", "--id", "record:retry", "--content", "retry", "--idempotency-key", "agent:retry")
	if errorCodeOf(m) != "signer_refused" {
		t.Fatal(m)
	}
	h.unchanged(h.owner, before)
	f.set("")
	h.add(h.owner, "record:retry", "retry")
}

// Default approval timeout is exercised through the actual CLI (120 seconds),
// then a repaired agent accepts the identical policy change without partial state.
func TestSSHAgentCLITimeoutAndRetry(t *testing.T) {
	t.Parallel()
	f := newCLIAgent(t)
	h := newAgentCLI(t, f.socket, f.pubLine())
	before := h.writeState(h.owner)
	s, _ := selectSpace(h.config(h.owner), "space:test")
	original, e := os.ReadFile(filepath.Join(s.ClonePath, "space.json"))
	if e != nil {
		t.Fatal(e)
	}
	args := []string{"policy", "grant", "--space", "space:test", "--identity", "reader:timeout", "--role", "reader"}
	f.set("hang")
	start := time.Now()
	m, _ := h.invoke(h.owner, 3, args...)
	if errorCodeOf(m) != "signer_unavailable" || time.Since(start) > 150*time.Second {
		t.Fatal(m, time.Since(start))
	}
	h.unchanged(h.owner, before)
	after, _ := os.ReadFile(filepath.Join(s.ClonePath, "space.json"))
	if !bytes.Equal(original, after) {
		t.Fatal("policy changed")
	}
	f.set("")
	h.invoke(h.owner, 0, args...)
}

// Rotation adds an independently held memory key under the same owner identity.
// The agent home signs the next policy; file-reader verification retains genesis.
func TestSSHAgentFileOwnerRotation(t *testing.T) {
	t.Parallel()
	h := newCLI(t)
	f := newCLIAgent(t)
	newHome := agentHome(t, h, "rotated-owner", "agent:owner", f.socket, f.pubLine())
	h.invoke(h.owner, 0, "keys", "register", "--space", "space:test", "--identity", "agent:owner", "--public-key", base64.StdEncoding.EncodeToString(f.public))
	before := h.localRepo(h.owner, "space:test").VerifiedPolicy().Policy().Version
	h.invoke(newHome, 0, "spaces", "add", "space:test", "--remote", h.remote, "--genesis", h.pin)
	h.invoke(newHome, 0, "policy", "grant", "--space", "space:test", "--identity", "reader:rotation", "--role", "reader")
	policy := h.localRepo(h.owner, "space:test").VerifiedPolicy().Policy()
	if policy.Version != before+1 || h.git(h.remote, "rev-list", "--max-parents=0", "main") != h.genesis {
		t.Fatal("rotation changed genesis or sequence")
	}
	s, _ := selectSpace(h.config(newHome), "space:test")
	b, e := os.ReadFile(filepath.Join(s.ClonePath, "space.json"))
	if e != nil {
		t.Fatal(e)
	}
	var signed struct {
		Signature sign.Signature `json:"signature"`
	}
	if e = json.Unmarshal(b, &signed); e != nil {
		t.Fatal(e)
	}
	if signed.Signature.Key != sign.KeyID(f.public) {
		t.Fatal("next policy not agent-signed")
	}
	h.connectReader()
	h.invoke(h.reader, 0, "check")
}

// Real OpenSSH is a foreground child with an explicit test socket, bounded
// lifetime, isolated environment and a dedicated ephemeral memory key. Cleanup
// kills this exact PID, waits for exit and verifies the endpoint is gone.
func TestSSHAgentRealOwnerFlow(t *testing.T) {
	t.Parallel()
	for _, tool := range []string{"ssh-agent", "ssh-add", "ssh-keygen"} {
		if _, e := exec.LookPath(tool); e != nil {
			t.Skip("real agent tool unavailable: " + tool)
		}
	}
	dir, e := os.MkdirTemp("", "ra-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	env := cleanEnv(dir)
	socket := filepath.Join(dir, "s")
	key := filepath.Join(dir, "memory")
	cmd := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key)
	cmd.Env = env
	if b, e := cmd.CombinedOutput(); e != nil {
		t.Fatal(e, string(b))
	}
	pub, e := os.ReadFile(key + ".pub")
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	agent := exec.CommandContext(ctx, "ssh-agent", "-D", "-a", socket)
	agent.Env = env
	if e = agent.Start(); e != nil {
		cancel()
		t.Fatal(e)
	}
	t.Cleanup(func() {
		_ = agent.Process.Kill()
		_ = agent.Wait()
		cancel()
		if agent.ProcessState == nil {
			t.Error("agent was not reaped")
		}
		if c, e := net.DialTimeout("unix", socket, 50*time.Millisecond); e == nil {
			c.Close()
			t.Error("real agent survived cleanup")
		}
		t.Logf("reaped foreground ssh-agent PID %d; no listener at %s", agent.Process.Pid, socket)
	})
	ready := false
	for end := time.Now().Add(3 * time.Second); time.Now().Before(end); {
		if st, e := os.Lstat(socket); e == nil && st.Mode()&os.ModeSocket != 0 {
			ready = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !ready {
		t.Fatal("foreground agent did not create explicit socket")
	}
	add := exec.CommandContext(ctx, "ssh-add", key)
	add.Env = nil
	for _, v := range env {
		if !strings.HasPrefix(v, "SSH_AUTH_SOCK=") {
			add.Env = append(add.Env, v)
		}
	}
	add.Env = append(add.Env, "SSH_AUTH_SOCK="+socket)
	if b, e := add.CombinedOutput(); e != nil {
		t.Fatal(e, string(b))
	}
	h := newAgentCLI(t, socket, string(pub))
	writer := filepath.Join(h.root, "real-writer")
	h.invoke(writer, 0, "keys", "init", "--identity", "agent:writer")
	agentOwnerFlow(t, h, writer)
}

// The source union remains closed: both/neither, unknown fields, relative
// sockets, malformed public bytes and null sources refuse without changing config.
// Init checks listing first, supports @public-file and never creates a key file
// or overwrites an existing key/config; a corrected listing is a valid retry.
func TestSSHAgentConfigurationAndInit(t *testing.T) {
	t.Parallel()
	h := newCLI(t)
	f := newCLIAgent(t)
	path := filepath.Join(h.root, "agent-config")
	args := []string{"keys", "init", "--identity", "agent:owner", "--ssh-agent", f.socket, "--public-key", f.pubLine()}
	f.set("missing")
	m, _ := h.invoke(path, 3, args...)
	if errorCodeOf(m) != "signer_key_missing" {
		t.Fatal(m)
	}
	for _, name := range []string{"config.json", "localkey.json"} {
		if _, e := os.Lstat(filepath.Join(path, name)); !errors.Is(e, os.ErrNotExist) {
			t.Fatal("failed init left state", name, e)
		}
	}
	f.set("")
	pubfile := filepath.Join(h.root, "memory.pub")
	if e := os.WriteFile(pubfile, []byte(f.pubLine()+"\n"), 0600); e != nil {
		t.Fatal(e)
	}
	args[len(args)-1] = "@" + pubfile
	h.invoke(path, 0, args...)
	original := h.configBytes(path)
	h.invoke(path, 3, args...)
	if h.configBytes(path) != original {
		t.Fatal("init overwrote config")
	}
	for _, mutate := range []func(map[string]any){
		func(c map[string]any) { c["key_file"] = filepath.Join(path, "localkey.json") }, func(c map[string]any) { delete(c, "signer") },
		func(c map[string]any) { c["signer"] = nil }, func(c map[string]any) { agentprofile.Object(c["signer"])["extra"] = true },
		func(c map[string]any) { agentprofile.Object(c["signer"])["socket"] = "relative" }, func(c map[string]any) { agentprofile.Object(c["signer"])["public_key"] = "bad" },
		func(c map[string]any) { agentprofile.Object(c["signer"])["kind"] = "other" }, func(c map[string]any) { c["extra"] = true },
	} {
		var c map[string]any
		if e := json.Unmarshal([]byte(original), &c); e != nil {
			t.Fatal(e)
		}
		mutate(c)
		b, _ := json.Marshal(c)
		if e := os.WriteFile(filepath.Join(path, "config.json"), b, 0600); e != nil {
			t.Fatal(e)
		}
		m, _ := h.invoke(path, 3, "keys", "show")
		if errorCodeOf(m) != "invalid_configuration" {
			t.Fatal(m)
		}
		after, _ := os.ReadFile(filepath.Join(path, "config.json"))
		if !bytes.Equal(after, b) {
			t.Fatal("bad config changed")
		}
	}
	if e := os.WriteFile(filepath.Join(path, "config.json"), []byte(original), 0600); e != nil {
		t.Fatal(e)
	}
	h.invoke(path, 0, "keys", "show")
	blocked := filepath.Join(h.root, "preexisting-key")
	if e := os.MkdirAll(blocked, 0700); e != nil {
		t.Fatal(e)
	}
	keyfile := filepath.Join(blocked, "localkey.json")
	if e := os.WriteFile(keyfile, []byte("preserve"), 0600); e != nil {
		t.Fatal(e)
	}
	h.invoke(blocked, 3, args...)
	after, _ := os.ReadFile(keyfile)
	if string(after) != "preserve" {
		t.Fatal("existing key changed")
	}
	// Malformed public inputs and invalid socket configuration leave no init
	// state. Each same-home valid retry succeeds once the input is corrected.
	for i, tc := range []struct{ socket, line, code string }{
		{f.socket, "ssh-rsa AAAA", "invalid_key"},
		{"relative", f.pubLine(), "invalid_configuration"},
		{f.socket + "missing", f.pubLine(), "signer_unavailable"},
		{f.socket, "@" + h.root, "invalid_key"},
	} {
		retryHome := filepath.Join(h.root, "retry-init-"+strconv64(int64(i)))
		m, _ := h.invoke(retryHome, 3, "keys", "init", "--identity", "agent:owner", "--ssh-agent", tc.socket, "--public-key", tc.line)
		if errorCodeOf(m) != tc.code {
			t.Fatal(m)
		}
		for _, name := range []string{"config.json", "localkey.json"} {
			if _, e := os.Lstat(filepath.Join(retryHome, name)); !errors.Is(e, os.ErrNotExist) {
				t.Fatal("invalid init left state", e)
			}
		}
		h.invoke(retryHome, 0, "keys", "init", "--identity", "agent:owner", "--ssh-agent", f.socket, "--public-key", f.pubLine())
	}

	// An agent home remains inspectable while its socket is unavailable.
	f.set("refused")
	h.invoke(path, 0, "keys", "show")
	k, e := sshagent.ParsePublicKey(f.pubLine())
	if e != nil || !bytes.Equal(k, f.public) {
		t.Fatal(e)
	}
}

// Every authored interface rejects a different configured identity before touching
// the agent. The paired valid request returns exactly the existing localfile
// signature for the same ephemeral key, canonical bytes and purpose.
func TestSSHAgentAllAuthorChecksAndLocalfileEquivalence(t *testing.T) {
	t.Parallel()
	h := newCLI(t)
	h.add(h.owner, "record:author", "author control")
	template, schemas, e := agentprofile.Load()
	if e != nil {
		t.Fatal(e)
	}
	record, e := sign.NewCanonicalRecord(h.stored(h.owner, "space:test", "record:author", 1), schemas, agentprofile.Array(template["domain_schemas"]))
	if e != nil {
		t.Fatal(e)
	}
	s, _ := selectSpace(h.config(h.owner), "space:test")
	message := h.git(s.ClonePath, "show", "-s", "--format=%B", "HEAD")
	parsed, refusal := kernel.DecodeJSON([]byte(strings.TrimPrefix(message, "swarma-memory transactions/1\n\n")))
	if refusal != nil {
		t.Fatal(refusal)
	}
	tx := agentprofile.Object(agentprofile.Array(parsed)[0])
	write, e := sign.NewCanonicalWrite(agentprofile.Object(tx["write"]), schemas, agentprofile.Array(template["domain_schemas"]))
	if e != nil {
		t.Fatal(e)
	}
	p := h.localRepo(h.owner, "space:test").VerifiedPolicy().Policy()
	policy, e := space.NewCanonicalPolicy(p)
	if e != nil {
		t.Fatal(e)
	}
	registration, e := space.NewCanonicalRegistration(p.Keys[0].Registration)
	if e != nil {
		t.Fatal(e)
	}
	advertisement, e := space.NewCanonicalAdvertisement(h.ad(h.owner, "space:test").Advertisement)
	if e != nil {
		t.Fatal(e)
	}
	directory, e := space.NewCanonicalDirectory(space.DirectoryEntry{Format: "swarma-memory-directory/1", DirectorySpace: "space:platform", SpaceID: "space:test", Version: 1, Status: "withdrawn", Author: "agent:owner"})
	if e != nil {
		t.Fatal(e)
	}
	f := newCLIAgent(t)
	good, e := sshagent.New("agent:owner", f.socket, f.public, time.Second)
	if e != nil {
		t.Fatal(e)
	}
	bad, e := sshagent.New("agent:other", f.socket, f.public, time.Second)
	if e != nil {
		t.Fatal(e)
	}
	// Test-only serialization materializes this fake agent's own ephemeral seed;
	// the production backend never receives it. No host key file is accessed.
	fixture := filepath.Join(h.root, "equivalent-localfile")
	if e = os.MkdirAll(fixture, 0700); e != nil {
		t.Fatal(e)
	}
	b, _ := json.Marshal(map[string]string{"identity": "agent:owner", "alg": "ed25519", "seed": base64.StdEncoding.EncodeToString(f.private.Seed())})
	if e = os.WriteFile(filepath.Join(fixture, "localkey.json"), b, 0600); e != nil {
		t.Fatal(e)
	}
	local := h.localKey(fixture)
	for _, tc := range []struct {
		purpose   string
		canonical []byte
		call      func(identityKey) (sign.Signature, error)
	}{
		{sign.RecordPurpose, record.Bytes(), func(k identityKey) (sign.Signature, error) { return k.Sign(record) }},
		{sign.WritePurpose, write.Bytes(), func(k identityKey) (sign.Signature, error) { return k.SignWrite(write) }},
		{sign.PolicyPurpose, policy.Bytes(), func(k identityKey) (sign.Signature, error) { return k.SignPolicy(policy) }},
		{sign.RegistrationPurpose, registration.Bytes(), func(k identityKey) (sign.Signature, error) { return k.SignRegistration(registration) }},
		{sign.AdvertisementPurpose, advertisement.Bytes(), func(k identityKey) (sign.Signature, error) { return k.SignAdvertisement(advertisement) }},
		{sign.DirectoryPurpose, directory.Bytes(), func(k identityKey) (sign.Signature, error) { return k.SignDirectory(directory) }},
	} {
		f.mu.Lock()
		before := len(f.purposes)
		f.mu.Unlock()
		sig, e := tc.call(bad)
		if classify(e).Code != "submitter_mismatch" || sig != (sign.Signature{}) {
			t.Fatal(tc.purpose, e)
		}
		f.mu.Lock()
		after := len(f.purposes)
		f.mu.Unlock()
		if after != before {
			t.Fatal("wrong author reached agent")
		}
		sig, e = tc.call(good)
		if e != nil {
			t.Fatal(e)
		}
		expected, e := tc.call(local)
		if e != nil || sig != expected {
			t.Fatal("backends differ", tc.purpose, e)
		}
		if e = (sign.Ed25519Verifier{}).Verify(tc.purpose, tc.canonical, sig, f.public); e != nil {
			t.Fatal(e)
		}
	}
}
