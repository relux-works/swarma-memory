package space

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func diagnosticGitEnv() []string {
	return []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.TempDir(), "TMPDIR=" + os.TempDir(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_CONFIG_NOSYSTEM=1", "GIT_ALLOW_PROTOCOL=file", "GIT_TERMINAL_PROMPT=0", "SSH_AUTH_SOCK=/dev/null", "LC_ALL=C"}
}

// A real Git success remains usable; a missing revision reports the command,
// exact exit status and a safe stderr reason without echoing its token-like arg.
func TestGitFailureDetails(t *testing.T) {
	dir := t.TempDir()
	env := diagnosticGitEnv()
	cmd := exec.Command("git", "init", "--bare", "--template=", dir)
	cmd.Env = env
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("init: %v: %s", err, out)
	}
	g := Git{Directory: dir, Environment: env}
	if out, err := g.run(context.Background(), nil, "rev-parse", "--is-bare-repository"); err != nil || strings.TrimSpace(string(out)) != "true" {
		t.Fatal("positive Git control", err)
	}
	secret := "ghp_" + strings.Repeat("A", 36)
	_, err := g.run(context.Background(), nil, "rev-parse", "--verify", secret)
	var failure *Error
	if !errors.As(err, &failure) || failure.Code != "git_failed" || failure.Command != "rev-parse" {
		t.Fatal("wrong typed failure", err)
	}
	if !strings.Contains(err.Error(), "exit 128") || !strings.Contains(err.Error(), "stderr:") || strings.Contains(err.Error(), secret) {
		t.Fatal("missing safe failure details", err)
	}
	if failure.ExitStatus == nil || *failure.ExitStatus != 128 || !strings.Contains(failure.Stderr, "Needed a single revision") || errorCode(fmt.Errorf("wrapped: %w", err)) != "git_failed" {
		t.Fatal("lost exit/reason/typed code", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "HEAD")); err != nil {
		t.Fatal("failed read damaged repository", err)
	}
}

// A controlled executable first proves that the env/credential plants reach
// stderr. The adapter must then retain status/command but no raw plant in any
// returned field, string, JSON or wrapped cause. No network or host keys are used.
func TestGitFailureRedactsChildPlants(t *testing.T) {
	dir := t.TempDir()
	program := filepath.Join(dir, "git")
	script := "#!/bin/sh\nprintf 'fatal: repository %s\\n' \"$2\" >&2\nprintf '%s\\n' \"$PLANTED_ENV\" >&2\nexit 37\n"
	if err := os.WriteFile(program, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	secret := "ghp_" + strings.Repeat("B", 36)
	user, password := "synthetic-user", "synthetic-password"
	remote := "https://" + user + ":" + password + "@example.invalid/private"
	env := append(diagnosticGitEnv(), "PLANTED_ENV="+secret)
	control := exec.Command(program, "clone", remote)
	control.Env = env
	raw, err := control.CombinedOutput()
	var exited *exec.ExitError
	if !errors.As(err, &exited) || exited.ExitCode() != 37 || !strings.Contains(string(raw), secret) || !strings.Contains(string(raw), remote) {
		t.Fatal("stderr control plants were not applied")
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	g := Git{Directory: dir, Environment: env}
	_, err = g.run(context.Background(), nil, "clone", remote)
	var failure *Error
	if !errors.As(err, &failure) || failure.Code != "git_failed" || failure.Command != "clone" || failure.ExitStatus == nil || *failure.ExitStatus != 37 || failure.Stderr != "fatal: repository [REDACTED]\n[REDACTED]" {
		t.Fatal("wrong safe failure", err)
	}
	wire, marshalErr := json.Marshal(failure)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	for _, rendered := range []string{err.Error(), fmt.Sprintf("%#v", failure), string(wire)} {
		for _, plant := range []string{secret, user, password, remote, "example.invalid", "private"} {
			if strings.Contains(rendered, plant) {
				t.Fatal("diagnostic exposed a planted value")
			}
		}
	}
	if errors.Unwrap(err) != nil {
		t.Fatal("raw child error escaped by unwrapping")
	}
}

// A missing working directory and a pre-canceled context report no normal exit,
// preserve safe launch reasons, and do not echo the private path/argument.
func TestGitFailureBeforeExit(t *testing.T) {
	root := t.TempDir()
	for _, canceled := range []bool{false, true} {
		ctx := context.Background()
		dir, reason := filepath.Join(root, "private-missing-path"), "no such file or directory"
		if canceled {
			var cancel context.CancelFunc
			ctx, cancel = context.WithCancel(ctx)
			cancel()
			dir, reason = root, "context canceled"
		}
		_, err := (Git{Directory: dir, Environment: diagnosticGitEnv()}).run(ctx, nil, "rev-parse", "private-argument")
		var failure *Error
		if !errors.As(err, &failure) || failure.ExitStatus == nil || *failure.ExitStatus != -1 || !strings.Contains(failure.Detail, reason) || failure.Stderr != "" || strings.Contains(err.Error(), root) || strings.Contains(err.Error(), "private-") {
			t.Fatal("wrong safe start failure", err)
		}
	}
}

// Strict literal redaction accepts known Git/OS reasons, removes arbitrary or
// localized text and terminal controls, and never exposes a cut secret prefix.
func TestGitStderrLimitsAndControls(t *testing.T) {
	for _, tc := range []struct{ raw, want string }{
		{"fatal: repository 'private-path' does not exist", "fatal: repository [REDACTED]: does not exist"},
		{"fatal: cannot copy 'private-path': Too many open files", "fatal: cannot copy [REDACTED]: Too many open files"},
		{"fatal: Needed a single revision\n", "fatal: [REDACTED]: Needed a single revision"},
		{"arbitrary private content\nошибка\n\x1b[31msecret\xff", "[REDACTED]\n[REDACTED]\n[REDACTED]"},
		{"", ""},
	} {
		if got := safeGitStderr(tc.raw); got != tc.want {
			t.Fatalf("wrong allowlisted excerpt: %q", got)
		}
	}
	var buffer gitStderrBuffer
	prefix := []byte("fatal: " + strings.Repeat("x", gitStderrCaptureLimit-10))
	secret := []byte("ghp_" + strings.Repeat("C", 36))
	for _, part := range [][]byte{prefix, secret, []byte(strings.Repeat("more", 10000))} {
		if n, err := buffer.Write(part); err != nil || n != len(part) {
			t.Fatal("bounded capture stopped draining child output", n, err)
		}
	}
	if len(buffer.data) != gitStderrCaptureLimit || !buffer.truncated || buffer.excerpt() != "fatal: [REDACTED] [truncated]" {
		t.Fatal("unbounded capture or leaked partial plant", buffer.excerpt())
	}
	long := safeGitStderr(strings.Repeat("fatal: private text\n", 1000))
	if len(long) > gitStderrExcerptLimit || !strings.HasSuffix(long, " [truncated]") || strings.Contains(long, "private") {
		t.Fatal("unbounded/unredacted excerpt")
	}
}

// Internal -c settings never become the reported subcommand or disclose values;
// unknown commands fail closed. Non-Git codes retain their existing strings.
func TestGitErrorCommandAndCode(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"clone", "private-remote"}, "clone"},
		{[]string{"-c", "private-setting", "-c", "another-setting", "commit", "--file=-"}, "commit"},
		{[]string{"private-command"}, "unknown"},
		{nil, "unknown"},
	} {
		if got := gitSubcommand(tc.args); got != tc.want {
			t.Fatal("wrong safe subcommand", got)
		}
	}
	if err := fail("history_rewritten"); err.Error() != "history_rewritten" || errorCode(err) != "history_rewritten" {
		t.Fatal("non-Git code changed", err)
	}
	legacy := &Error{Code: "git_failed", Command: "clone"}
	if !strings.Contains(legacy.Error(), "exit unknown") {
		t.Fatal("unknown legacy status misreported as a success exit")
	}
}
