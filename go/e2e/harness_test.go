package e2e_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

var memoryBinary string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "memory-e2e-build-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "e2e build directory:", err)
		os.Exit(1)
	}
	memoryBinary = filepath.Join(dir, "memory")
	cmd := exec.Command("go", "build", "-buildvcs=false", "-o", memoryBinary, "../cmd/memory")
	cmd.Env = isolatedEnv(dir)
	if output, err := cmd.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "e2e build: %v\n%s", err, output)
		os.RemoveAll(dir)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// Allow only toolchain/cache/temp variables. Ambient credentials, identity,
// Git/Go configuration and key-agent settings never enter a fixture process.
func isolatedEnv(home string) []string {
	env := []string{}
	for _, key := range []string{"PATH", "TMPDIR", "TMP", "TEMP", "GOCACHE", "GOMODCACHE", "GOROOT", "GOPATH", "GOMAXPROCS", "CGO_ENABLED", "CC", "CXX", "SDKROOT", "MACOSX_DEPLOYMENT_TARGET"} {
		if value, ok := os.LookupEnv(key); ok {
			env = append(env, key+"="+value)
		}
	}
	return append(env, "HOME="+home, "GOENV=off", "GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off", "LANG=C", "LC_ALL=C", "TZ=UTC", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_CONFIG_NOSYSTEM=1", "GIT_ALLOW_PROTOCOL=file", "GIT_TERMINAL_PROMPT=0", "GIT_SSH_COMMAND=false", "SSH_AUTH_SOCK=/dev/null")
}

type agent struct {
	t                    *testing.T
	root, home, identity string
	env                  []string
	publicKey, keyID     string
}

type fixture struct {
	t              *testing.T
	root           string
	owner, a, b    *agent
	allowedSigners string
	sshPublicLines []string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{t: t, root: t.TempDir()}
	f.allowedSigners = filepath.Join(f.root, "allowed_signers")
	f.owner = f.newAgent("owner")
	f.a = f.newAgent("a")
	f.b = f.newAgent("b")
	return f
}

func (f *fixture) newAgent(name string) *agent {
	return f.newAgentIdentity(name, "agent:"+name)
}

func (f *fixture) newAgentIdentity(name, identity string) *agent {
	f.t.Helper()
	root := filepath.Join(f.root, name)
	if err := os.MkdirAll(root, 0700); err != nil {
		f.t.Fatal(err)
	}
	a := &agent{t: f.t, root: root, home: filepath.Join(root, "memory"), identity: identity}
	a.env = isolatedEnv(root)
	sshKey := filepath.Join(root, "commit_signer")
	a.exec(root, "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", sshKey)
	public, err := os.ReadFile(sshKey + ".pub")
	if err != nil {
		f.t.Fatal(err)
	}
	email := name + "@example.invalid"
	f.sshPublicLines = append(f.sshPublicLines, email+" "+strings.TrimSpace(string(public)))
	if err := os.WriteFile(f.allowedSigners, []byte(strings.Join(f.sshPublicLines, "\n")+"\n"), 0600); err != nil {
		f.t.Fatal(err)
	}
	settings := [][2]string{
		{"user.signingkey", sshKey}, {"gpg.format", "ssh"}, {"gpg.ssh.program", "ssh-keygen"},
		{"gpg.ssh.allowedSignersFile", f.allowedSigners}, {"core.hooksPath", "/dev/null"},
		// The gate's signature checks require an explicit -S from the caller.
		{"commit.gpgsign", "false"},
	}
	a.env = append(a.env, "GIT_AUTHOR_NAME=E2E "+name, "GIT_AUTHOR_EMAIL="+email, "GIT_COMMITTER_NAME=E2E "+name, "GIT_COMMITTER_EMAIL="+email, fmt.Sprintf("GIT_CONFIG_COUNT=%d", len(settings)))
	for i, setting := range settings {
		a.env = append(a.env, fmt.Sprintf("GIT_CONFIG_KEY_%d=%s", i, setting[0]), fmt.Sprintf("GIT_CONFIG_VALUE_%d=%s", i, setting[1]))
	}
	key := object(f.t, a.run(0, "keys", "init", "--identity", a.identity).Data, "identity", "key_id", "algorithm", "public_key")
	a.publicKey = text(f.t, key["public_key"])
	a.keyID = text(f.t, key["key_id"])
	return a
}

func (a *agent) exec(dir, program string, args ...string) string {
	a.t.Helper()
	cmd := exec.Command(program, args...)
	cmd.Dir, cmd.Env = dir, a.env
	output, err := cmd.CombinedOutput()
	if err != nil {
		a.t.Fatalf("fixture %s %v failed: %v\n%s", program, args, err, output)
	}
	return strings.TrimSpace(string(output))
}

func (a *agent) git(dir string, args ...string) string {
	a.t.Helper()
	return a.exec(dir, "git", args...)
}

type wireError struct {
	Code string `json:"code"`
	Exit int    `json:"exit"`
}

type reply struct {
	Type           string          `json:"type"`
	Command        string          `json:"command"`
	Classification string          `json:"data_classification"`
	Data           json.RawMessage `json:"data"`
	Error          *wireError      `json:"error"`
	raw            []byte
}

// closedObject rejects unknown, missing and duplicate keys, plus trailing JSON.
// It intentionally does not reuse a production parser or expected-result helper.
func closedObject(raw []byte, fields ...string) (map[string]json.RawMessage, error) {
	if !utf8.Valid(raw) {
		return nil, fmt.Errorf("invalid UTF-8")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	first, err := d.Token()
	if err != nil || first != json.Delim('{') {
		return nil, fmt.Errorf("expected object")
	}
	out := map[string]json.RawMessage{}
	for d.More() {
		key, err := d.Token()
		if err != nil {
			return nil, err
		}
		name, ok := key.(string)
		if !ok || out[name] != nil {
			return nil, fmt.Errorf("invalid/duplicate key")
		}
		var value json.RawMessage
		if err := d.Decode(&value); err != nil {
			return nil, err
		}
		out[name] = value
	}
	if _, err := d.Token(); err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, fmt.Errorf("trailing JSON")
	}
	if len(out) != len(fields) {
		return nil, fmt.Errorf("unexpected object fields")
	}
	for _, field := range fields {
		if _, ok := out[field]; !ok {
			return nil, fmt.Errorf("missing field %s", field)
		}
	}
	return out, nil
}

func object(t *testing.T, raw []byte, fields ...string) map[string]json.RawMessage {
	t.Helper()
	m, err := closedObject(raw, fields...)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func text(t *testing.T, raw []byte) string {
	t.Helper()
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatal(err)
	}
	return s
}

func (a *agent) run(wantExit int, args ...string) reply {
	a.t.Helper()
	return a.start("", args...).finish(wantExit)
}

type invocation struct {
	a              *agent
	args           []string
	cmd            *exec.Cmd
	stdout, stderr bytes.Buffer
	cancel         context.CancelFunc
}

func (a *agent) start(input string, args ...string) *invocation {
	a.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	c := &invocation{a: a, args: args, cancel: cancel}
	c.cmd = exec.CommandContext(ctx, memoryBinary, append([]string{"--home", a.home, "--json"}, args...)...)
	c.cmd.Dir, c.cmd.Env = a.root, a.env
	c.cmd.Stdin = strings.NewReader(input)
	c.cmd.Stdout, c.cmd.Stderr = &c.stdout, &c.stderr
	c.cmd.WaitDelay = time.Second
	if err := c.cmd.Start(); err != nil {
		cancel()
		a.t.Fatal(err)
	}
	a.t.Cleanup(func() {
		cancel()
		if c.cmd.ProcessState == nil {
			_ = c.cmd.Process.Kill()
			_ = c.cmd.Wait()
		}
	})
	return c
}

func (c *invocation) finish(wantExit int) reply {
	a, args := c.a, c.args
	a.t.Helper()
	err := c.cmd.Wait()
	c.cancel()
	if err != nil {
		if _, ok := err.(*exec.ExitError); !ok {
			a.t.Fatal(err)
		}
	}
	if wantExit < 0 {
		wantExit = c.cmd.ProcessState.ExitCode()
		if wantExit != 0 && wantExit != 3 {
			a.t.Fatalf("unexpected race exit %d: %s %s", wantExit, &c.stdout, &c.stderr)
		}
	}
	if c.cmd.ProcessState.ExitCode() != wantExit {
		a.t.Fatalf("%s memory %v: exit %d want %d\nstdout: %s\nstderr: %s", a.identity, args, c.cmd.ProcessState.ExitCode(), wantExit, &c.stdout, &c.stderr)
	}
	object(a.t, c.stdout.Bytes(), "type", "command", "data_classification", "data", "error")
	var result reply
	if err := json.Unmarshal(c.stdout.Bytes(), &result); err != nil {
		a.t.Fatal(err)
	}
	if result.Command != args[0] || result.Classification != "data" {
		a.t.Fatal("wrong command/classification", result)
	}
	if wantExit == 0 {
		if result.Type != "result" || result.Error != nil || c.stderr.Len() != 0 {
			a.t.Fatal("unexpected success shape", result, c.stderr.String())
		}
	} else {
		if result.Type != "error" || result.Error == nil || result.Error.Code == "" || result.Error.Exit != wantExit || c.stderr.Len() == 0 {
			a.t.Fatal("unexpected refusal shape", result)
		}
		var envelope map[string]json.RawMessage
		json.Unmarshal(c.stdout.Bytes(), &envelope)
		object(a.t, envelope["error"], "code", "exit")
	}
	result.raw = append([]byte(nil), c.stdout.Bytes()...)
	return result
}

func (a *agent) read(command string, exit int) reply {
	a.t.Helper()
	args := []string{command}
	if command == "recall" {
		args = append(args, "*")
	}
	return a.run(exit, append(args, "--at", "2026-10-19T00:00:00Z")...)
}

func refused(t *testing.T, r reply, code string) {
	t.Helper()
	if r.Error == nil || r.Error.Code != code {
		t.Fatalf("expected %s; got %+v", code, r.Error)
	}
}

type project struct {
	id, remote, pin, genesis string
}

func (f *fixture) project(id, name string) project {
	f.t.Helper()
	p := project{id: id, remote: filepath.Join(f.root, name+".git")}
	f.owner.git(f.root, "init", "--bare", "--initial-branch=main", p.remote)
	summary := object(f.t, f.owner.run(0, "spaces", "init", id, "--remote", p.remote, "--kind", "project").Data, "id", "policy", "policy_digest", "cursor", "diagnostic_count", "diagnostics")
	p.pin, p.genesis = text(f.t, summary["policy_digest"]), text(f.t, summary["cursor"])
	for _, a := range []*agent{f.a, f.b} {
		f.owner.run(0, "keys", "register", "--space", id, "--identity", a.identity, "--public-key", a.publicKey)
		for _, role := range []string{"reader", "writer"} {
			f.owner.run(0, "policy", "grant", "--space", id, "--identity", a.identity, "--role", role)
		}
		a.run(0, "spaces", "add", id, "--remote", p.remote, "--branch", "main", "--genesis", p.pin, "--kind", "project")
	}
	f.verifyCommits(p)
	return p
}

func (f *fixture) verifyCommits(p project) {
	f.t.Helper()
	for _, commit := range strings.Fields(f.owner.git(p.remote, "rev-list", "main")) {
		if verdict := f.owner.git(p.remote, "log", "-1", "--format=%G?", commit); verdict != "G" {
			f.t.Fatal("fixture commit not signed/verified", commit, verdict)
		}
	}
}

func clonePath(a *agent, p project) string {
	a.t.Helper()
	list := object(a.t, a.run(0, "spaces", "list").Data, "spaces")
	var spaces []json.RawMessage
	if err := json.Unmarshal(list["spaces"], &spaces); err != nil {
		a.t.Fatal(err)
	}
	for _, raw := range spaces {
		space := object(a.t, raw, "id", "remote", "branch", "clone_path", "cache_path", "genesis_digest", "kind")
		if text(a.t, space["id"]) == p.id {
			path := text(a.t, space["clone_path"])
			rel, err := filepath.Rel(a.home, path)
			if err != nil || filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
				a.t.Fatal("clone escaped fixture home")
			}
			return path
		}
	}
	a.t.Fatal("configured clone missing")
	return ""
}
