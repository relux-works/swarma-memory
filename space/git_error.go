package space

import (
	"fmt"
	"strings"
)

const gitStderrCaptureLimit = 4096
const gitStderrExcerptLimit = 512

// Drain all child output without retaining an unbounded or partly exposed secret.
// Redaction uses fixed literals, so a secret cut at the capture boundary is safe.
type gitStderrBuffer struct {
	data      []byte
	truncated bool
}

func (b *gitStderrBuffer) Write(p []byte) (int, error) {
	n := min(len(p), gitStderrCaptureLimit-len(b.data))
	b.data = append(b.data, p[:n]...)
	b.truncated = b.truncated || n < len(p)
	return len(p), nil
}

func (b *gitStderrBuffer) excerpt() string {
	text := safeGitStderr(string(b.data))
	if b.truncated {
		text += " [truncated]"
	}
	return boundedGitExcerpt(text)
}

func boundedGitExcerpt(s string) string {
	if len(s) > gitStderrExcerptLimit {
		return s[:gitStderrExcerptLimit-len(" [truncated]")] + " [truncated]"
	}
	return s
}

// Only fixed English Git prefixes and OS reason suffixes can leave the adapter.
// All variable text (including credentials, arbitrary content and local paths)
// is replaced wholesale; unknown/localized diagnostics are fully redacted.
func safeGitStderr(raw string) string {
	var lines []string
	for _, line := range strings.Split(raw, "\n") {
		if line == "" {
			continue
		}
		safe := "[REDACTED]"
		for _, prefix := range []string{
			"fatal: not a git repository", "fatal: repository ", "fatal: destination path ",
			"fatal: could not create work tree dir ", "fatal: unable to create ",
			"fatal: cannot copy ", "fatal: cannot stat ", "fatal: cannot fork",
			"fatal: cannot run ", "fatal: unable to access ", "error: cannot fork",
			"error: cannot spawn ", "error: cannot run ", "fatal: ", "error: ", "warning: ",
		} {
			if strings.HasPrefix(line, prefix) {
				safe = prefix + "[REDACTED]"
				break
			}
		}
		for _, reason := range []string{
			"No such file or directory", "Permission denied", "File exists",
			"Resource temporarily unavailable", "Too many open files", "No space left on device",
			"Input/output error", "Cannot allocate memory", "Operation not permitted",
			"no such file or directory", "permission denied", "resource temporarily unavailable",
			"too many open files", "cannot allocate memory", "context canceled", "context deadline exceeded",
			"does not exist", "already exists and is not an empty directory.",
			"Needed a single revision", "unable to create thread", "unable to fork",
			"Authentication failed", "Could not read from remote repository.",
			"unknown revision or path not in the working tree.",
		} {
			if strings.HasSuffix(line, reason) {
				safe += ": " + reason
				break
			}
		}
		lines = append(lines, safe)
	}
	return boundedGitExcerpt(strings.Join(lines, "\n"))
}

// Classify only recognized Git/transport diagnostics into fixed literals. No
// operand or protocol text is retained. This describes the reported failure,
// not an independent diagnosis of the remote or its authorization policy.
func gitFailureCause(command string, stderr, stdout []byte) string {
	if command == "push" {
		// Porcelain puts rejection reasons on stdout. Inspect a bounded prefix;
		// a reason beyond it remains unknown, never replaced with raw output.
		for _, line := range strings.Split(string(stdout[:min(len(stdout), gitStderrCaptureLimit)]), "\n") {
			fields := strings.Split(line, "\t")
			if len(fields) == 3 && fields[0] == "!" && (fields[2] == "[rejected] (non-fast-forward)" || fields[2] == "[rejected] (fetch first)") {
				return "non_fast_forward"
			}
		}
	}
	for _, line := range strings.Split(strings.ToLower(string(stderr)), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "fatal: unable to create ") && strings.Contains(line, "index.lock") && strings.HasSuffix(strings.TrimSuffix(line, "."), "file exists"):
			return "index_locked"
		case strings.HasPrefix(line, "fatal: couldn't find remote ref "):
			return "remote_ref_missing"
		case command == "push" && strings.HasPrefix(line, "! ") && strings.Contains(line, "[rejected]") && (strings.HasSuffix(line, "(non-fast-forward)") || strings.HasSuffix(line, "(fetch first)")):
			return "non_fast_forward"
		case strings.HasPrefix(line, "fatal: authentication failed") || strings.Contains(line, ": permission denied (publickey"):
			return "auth_failed"
		case strings.HasSuffix(strings.TrimSuffix(line, "."), ": permission denied") || strings.HasSuffix(strings.TrimSuffix(line, "."), ": operation not permitted"):
			return "permission_denied"
		case strings.HasPrefix(line, "fatal: not a git repository"):
			return "not_a_repository"
		case line == "fatal: needed a single revision" || (strings.HasPrefix(line, "fatal: ambiguous argument ") && strings.HasSuffix(line, "unknown revision or path not in the working tree.")):
			return "revision_missing"
		case (strings.HasPrefix(line, "fatal: repository ") && strings.HasSuffix(line, "does not exist")) || strings.HasSuffix(line, "does not appear to be a git repository") || strings.HasPrefix(line, "ssh: could not resolve hostname ") || (strings.HasPrefix(line, "fatal: unable to access ") && (strings.Contains(line, "could not resolve host:") || strings.Contains(line, "failed to connect to "))):
			return "remote_unreachable"
		}
	}
	return "unknown"
}

// Arguments are internal, but keep future unexpected input out of diagnostics.
func gitSubcommand(args []string) string {
	for len(args) >= 2 && args[0] == "-c" {
		args = args[2:]
	}
	if len(args) > 0 {
		switch args[0] {
		case "clone", "rev-parse", "rev-list", "fetch", "push", "status", "switch", "restore", "rm", "add", "commit", "write-tree", "verify-commit", "symbolic-ref", "ls-tree", "cat-file", "diff-tree", "show", "ls-remote":
			return args[0]
		}
	}
	return "unknown"
}

func (e *Error) Error() string {
	if e.Code != "git_failed" {
		return e.Code
	}
	status := "unknown"
	if e.ExitStatus != nil {
		status = fmt.Sprint(*e.ExitStatus)
	}
	message := fmt.Sprintf("%s: git %s (exit %s)", e.Code, e.Command, status)
	if e.Cause != "" {
		message += "; cause: " + e.Cause
	}
	if e.Detail != "" {
		message += ": " + e.Detail
	}
	if e.Stderr != "" {
		message += "; stderr: " + e.Stderr
	}
	return message
}
