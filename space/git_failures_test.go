package space

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func diagnosticCommand(t *testing.T, g Git, args ...string) string {
	t.Helper()
	out, err := g.run(context.Background(), nil, args...)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(out))
}

func diagnosticFailure(t *testing.T, g Git, cause string, plants []string, args ...string) {
	t.Helper()
	out, err := g.run(context.Background(), nil, args...)
	var failure *Error
	if !errors.As(err, &failure) || errorCode(err) != "git_failed" || failure.ExitStatus == nil || *failure.ExitStatus <= 0 || out != nil {
		t.Fatalf("expected typed Git rejection, got %v", err)
	}
	if failure.Cause != cause || !strings.Contains(err.Error(), "cause: "+cause) {
		t.Errorf("lost fixed cause %s: %v", cause, err)
	}
	wire, err := json.Marshal(failure)
	if err != nil {
		t.Fatal(err)
	}
	for _, rendered := range []string{failure.Error(), string(wire)} {
		for _, plant := range plants {
			if strings.Contains(rendered, plant) {
				t.Fatal("diagnostic disclosed an operand or credential plant")
			}
		}
	}
	if errors.Unwrap(failure) != nil {
		t.Fatal("raw cause escaped")
	}
}

// Real Git failures retain fixed categories, never their private operands.
// Valid neighbors and state checks distinguish useful rejection from rejecting
// every command or damaging the index/remote. Commits are isolated test fixtures.
func TestGitFailureCategoriesRealGit(t *testing.T) {
	root := t.TempDir()
	env := append(diagnosticGitEnv(), "GIT_AUTHOR_NAME=Diagnostic Test", "GIT_AUTHOR_EMAIL=diagnostic@example.invalid", "GIT_COMMITTER_NAME=Diagnostic Test", "GIT_COMMITTER_EMAIL=diagnostic@example.invalid")
	g := Git{Directory: root, Environment: env}
	diagnosticCommand(t, g, "init", "--template=", "--initial-branch=main", ".")
	commit := func() string {
		diagnosticCommand(t, g, "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null", "commit", "--allow-empty", "-m", "Synthetic diagnostic fixture")
		return diagnosticCommand(t, g, "rev-parse", "HEAD")
	}
	first := commit()
	second := commit()
	if err := os.WriteFile(filepath.Join(root, "operand-file"), []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	remote := filepath.Join(t.TempDir(), "operand-remote.git")
	diagnosticCommand(t, g, "init", "--bare", "--template=", remote)
	diagnosticCommand(t, g, "push", "--porcelain", remote, second+":refs/heads/main")

	t.Run("not_a_repository", func(t *testing.T) {
		outside := Git{Directory: t.TempDir(), Environment: env}
		diagnosticFailure(t, outside, "not_a_repository", []string{outside.Directory}, "rev-parse", "--show-toplevel")
		diagnosticCommand(t, g, "rev-parse", "--show-toplevel")
	})
	t.Run("revision_missing", func(t *testing.T) {
		ref := "operand-missing-revision"
		diagnosticFailure(t, g, "revision_missing", []string{ref, root}, "rev-parse", "--verify", ref)
		if diagnosticCommand(t, g, "rev-parse", "HEAD") != second {
			t.Fatal("failed read changed HEAD")
		}
	})
	t.Run("remote_ref_missing", func(t *testing.T) {
		ref := "operand-missing-remote-ref"
		diagnosticFailure(t, g, "remote_ref_missing", []string{ref, root, remote}, "fetch", remote, ref)
		diagnosticCommand(t, g, "fetch", remote, "main")
		if diagnosticCommand(t, g, "rev-parse", "FETCH_HEAD") != second {
			t.Fatal("positive fetch did not resolve remote head")
		}
	})
	t.Run("non_fast_forward", func(t *testing.T) {
		for _, porcelain := range []bool{false, true} {
			args := []string{"push"}
			if porcelain {
				args = append(args, "--porcelain")
			}
			args = append(args, remote, first+":refs/heads/main")
			diagnosticFailure(t, g, "non_fast_forward", []string{root, remote, first, "refs/heads/main"}, args...)
			bare := Git{Directory: remote, Environment: env}
			if diagnosticCommand(t, bare, "rev-parse", "refs/heads/main") != second {
				t.Fatal("rejected push changed remote")
			}
		}
		diagnosticCommand(t, g, "push", "--porcelain", remote, second+":refs/heads/main")
	})
	t.Run("index_locked", func(t *testing.T) {
		lock := filepath.Join(root, ".git", "index.lock")
		before, err := os.ReadFile(filepath.Join(root, ".git", "index"))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(lock, []byte("owned-lock"), 0600); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Remove(lock) })
		diagnosticFailure(t, g, "index_locked", []string{root, "operand-file"}, "add", "operand-file")
		if body, err := os.ReadFile(lock); err != nil || string(body) != "owned-lock" {
			t.Fatal("failed add changed the existing lock")
		}
		after, err := os.ReadFile(filepath.Join(root, ".git", "index"))
		if err != nil || string(before) != string(after) {
			t.Fatal("failed add changed the index")
		}
		if err := os.Remove(lock); err != nil {
			t.Fatal(err)
		}
		diagnosticCommand(t, g, "add", "operand-file")
	})
	t.Run("permission_denied", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("filesystem permission rejection requires a non-root user")
		}
		gitDir := filepath.Join(root, ".git")
		before, err := os.ReadFile(filepath.Join(gitDir, "index"))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(gitDir, 0500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(gitDir, 0700) })
		diagnosticFailure(t, g, "permission_denied", []string{root, "operand-file"}, "add", "operand-file")
		after, err := os.ReadFile(filepath.Join(gitDir, "index"))
		if err != nil || string(before) != string(after) {
			t.Fatal("permission rejection changed index")
		}
		if err := os.Chmod(gitDir, 0700); err != nil {
			t.Fatal(err)
		}
		diagnosticCommand(t, g, "add", "operand-file")
	})
	t.Run("remote_unreachable", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "operand-missing.git")
		diagnosticFailure(t, g, "remote_unreachable", []string{missing}, "fetch", missing, "main")
		diagnosticCommand(t, g, "fetch", remote, "main")
	})
}

// Unrecognized output and a reason planted in the ref field cannot become a
// porcelain rejection category. Only the exact status field is interpreted.
func TestGitFailureCategoryProtocol(t *testing.T) {
	for _, tc := range []struct{ command, stderr, stdout, want string }{
		{"push", "", "!\tprivate-ref:refs/heads/main\t[rejected] (non-fast-forward)\n", "non_fast_forward"},
		{"push", "", "!\tprivate-ref:refs/heads/main\t[rejected] (fetch first)\n", "non_fast_forward"},
		{"push", "", "!\t[rejected] (non-fast-forward)\t[remote rejected] (hook declined)\n", "unknown"},
		{"push", "", " \tprivate-ref:refs/heads/main\t[rejected] (non-fast-forward)\n", "unknown"},
		{"fetch", "", "!\tprivate-ref:refs/heads/main\t[rejected] (non-fast-forward)\n", "unknown"},
		{"push", "hint: non-fast-forward\n", "", "unknown"},
		{"push", "private operand with index.lock File exists.\n", "", "unknown"},
		{"push", "ошибка\n", "private output", "unknown"},
		{"push", "", strings.Repeat("x", gitStderrCaptureLimit) + "\n!\tref:ref\t[rejected] (non-fast-forward)\n", "unknown"},
	} {
		if got := gitFailureCause(tc.command, []byte(tc.stderr), []byte(tc.stdout)); got != tc.want {
			t.Fatalf("unexpected fixed category %q, want %q", got, tc.want)
		}
	}
}

// Confirm that the controlled child emits credential/ref/env plants on stdout,
// then retain only its porcelain category through the production failure path.
func TestGitFailurePorcelainRedactsChildPlants(t *testing.T) {
	root := t.TempDir()
	program := filepath.Join(root, "git")
	script := "#!/bin/sh\nprintf '!\\t%s\\t[rejected] (non-fast-forward)\\n' \"$PLANTED_REF\"\nprintf '%s\\n' \"$PLANTED_ENV\"\nexit 1\n"
	if err := os.WriteFile(program, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	ref := "https://operand-user:operand-password@operand-host/private:refs/heads/private"
	secret := "ghp_" + strings.Repeat("D", 36)
	env := append(diagnosticGitEnv(), "PLANTED_REF="+ref, "PLANTED_ENV="+secret)
	control := exec.Command(program)
	control.Env = env
	raw, err := control.Output()
	var exited *exec.ExitError
	if !errors.As(err, &exited) || exited.ExitCode() != 1 || !strings.Contains(string(raw), ref) || !strings.Contains(string(raw), secret) {
		t.Fatal("stdout plants were not applied")
	}
	t.Setenv("PATH", root+string(os.PathListSeparator)+os.Getenv("PATH"))
	diagnosticFailure(t, Git{Directory: root, Environment: env}, "non_fast_forward", []string{root, secret, ref, "operand-user", "operand-password", "operand-host", "private"}, "push", "--porcelain")
}

// Real Git invokes an offline SSH transport fixture. These standard transport
// messages model authentication/DNS failure, not live credentials or networking;
// a valid file transport remains usable alongside both rejected operations.
func TestGitFailureTransportCategories(t *testing.T) {
	root := t.TempDir()
	g := Git{Directory: root, Environment: diagnosticGitEnv()}
	diagnosticCommand(t, g, "init", "--bare", "--template=", ".")
	for _, tc := range []struct{ cause, message string }{
		{"auth_failed", "operand-user@operand-host: Permission denied (publickey)."},
		{"auth_failed", "fatal: Authentication failed for 'https://operand-user:operand-password@operand-host/private'"},
		{"remote_unreachable", "ssh: Could not resolve hostname operand-host: nodename nor servname provided, or not known"},
	} {
		t.Run(tc.cause+tc.message[:3], func(t *testing.T) {
			helper := filepath.Join(t.TempDir(), "ssh-fixture")
			if err := os.WriteFile(helper, []byte("#!/bin/sh\nprintf '%s\\n' \"$TRANSPORT_MESSAGE\" >&2\nexit 255\n"), 0700); err != nil {
				t.Fatal(err)
			}
			remote := "ssh://operand-user:operand-password@operand-host/private"
			transport := g
			transport.Environment = append(append([]string{}, g.Environment...), "GIT_ALLOW_PROTOCOL=ssh", "GIT_SSH_VARIANT=ssh", "GIT_SSH="+helper, "TRANSPORT_MESSAGE="+tc.message)
			diagnosticFailure(t, transport, tc.cause, []string{root, helper, "operand-user", "operand-password", "operand-host", "private"}, "ls-remote", remote)
			diagnosticCommand(t, g, "ls-remote", root)
		})
	}
}

// A started child ignores catchable termination signals. With a descendant,
// that descendant holds both output descriptors indefinitely. Cancellation must
// still return git_failed within one second; every owned PID is explicitly killed.
func TestGitFailureCancellationDrain(t *testing.T) {
	for _, descendant := range []bool{false, true} {
		t.Run(strconv.FormatBool(descendant), func(t *testing.T) {
			root := t.TempDir()
			exe, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			program := filepath.Join(root, "git")
			if err := os.WriteFile(program, []byte("#!/bin/sh\nexec \"$DRAIN_EXE\" -test.run=^TestGitDrainHelper$\n"), 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", root+string(os.PathListSeparator)+os.Getenv("PATH"))
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			env := append(diagnosticGitEnv(), "DRAIN_EXE="+exe, "DRAIN_ROOT="+root, "DRAIN_ROLE=parent", "DRAIN_DESCENDANT="+strconv.FormatBool(descendant))
			done := make(chan error, 1)
			go func() { _, err := (Git{Directory: root, Environment: env}).run(ctx, nil, "fetch"); done <- err }()
			killOwned := func() {
				for _, role := range []string{"parent", "descendant"} {
					if data, err := os.ReadFile(filepath.Join(root, role)); err == nil {
						pid, err := strconv.Atoi(string(data))
						if err == nil && pid > 0 {
							process, _ := os.FindProcess(pid)
							_ = process.Kill()
						}
					}
				}
			}
			t.Cleanup(killOwned)
			ready := "parent"
			if descendant {
				ready = "descendant"
			}
			deadline := time.Now().Add(10 * time.Second)
			for {
				if _, err := os.Stat(filepath.Join(root, ready)); err == nil {
					break
				}
				if time.Now().After(deadline) {
					cancel()
					t.Fatal("fixture did not confirm process readiness")
				}
				time.Sleep(5 * time.Millisecond)
			}
			canceledAt := time.Now()
			cancel()
			select {
			case err = <-done:
			case <-time.After(time.Second):
				killOwned()
				err = <-done
				t.Error("cancellation exceeded the one-second test bound")
			}
			t.Logf("adapter returned %s after cancellation (descendant=%t)", time.Since(canceledAt), descendant)
			var failure *Error
			if !errors.As(err, &failure) || failure.Code != "git_failed" || failure.ExitStatus == nil || *failure.ExitStatus != -1 || !strings.Contains(failure.Stderr, "[REDACTED]") || strings.Contains(failure.Error(), "operand-secret") {
				t.Fatal("wrong cancellation diagnostic", err)
			}
		})
	}
}

// Test-only subprocess entrypoint: no host keys, networking or shared processes.
func TestGitDrainHelper(t *testing.T) {
	root, role := os.Getenv("DRAIN_ROOT"), os.Getenv("DRAIN_ROLE")
	if root == "" || role == "" {
		return
	}
	signal.Ignore(os.Interrupt, syscall.SIGTERM)
	_, _ = os.Stderr.WriteString("operand-secret\n")
	if err := os.WriteFile(filepath.Join(root, role), []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
		os.Exit(2)
	}
	if role == "parent" && os.Getenv("DRAIN_DESCENDANT") == "true" {
		child := exec.Command(os.Args[0], "-test.run=^TestGitDrainHelper$")
		child.Env = append(os.Environ(), "DRAIN_ROLE=descendant")
		child.Stdout, child.Stderr = os.Stdout, os.Stderr
		if err := child.Run(); err != nil {
			os.Exit(3)
		}
	}
	for {
		time.Sleep(time.Hour)
	}
}
