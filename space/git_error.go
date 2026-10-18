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

// Arguments are internal, but keep future unexpected input out of diagnostics.
func gitSubcommand(args []string) string {
	for len(args) >= 2 && args[0] == "-c" {
		args = args[2:]
	}
	if len(args) > 0 {
		switch args[0] {
		case "clone", "rev-parse", "rev-list", "fetch", "push", "status", "switch", "restore", "rm", "add", "commit", "write-tree", "verify-commit", "symbolic-ref", "ls-tree", "cat-file", "diff-tree", "show":
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
	if e.Detail != "" {
		message += ": " + e.Detail
	}
	if e.Stderr != "" {
		message += "; stderr: " + e.Stderr
	}
	return message
}
