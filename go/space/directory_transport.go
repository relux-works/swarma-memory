package space

import (
	"context"
	"net/url"
	"path/filepath"
	"strings"
	"unicode"
)

// DirectoryRemote permits no remote helpers or option-shaped locations. File
// transports require an explicit caller test environment allowing file.
func DirectoryRemote(remote string, environment []string) error {
	file := directoryFileAllowed(environment)
	if remote == "" || strings.HasPrefix(remote, "-") || strings.Contains(remote, "::") && !strings.Contains(remote, "://") || strings.ContainsFunc(remote, unicode.IsControl) {
		return fail("directory_transport")
	}
	u, e := url.Parse(remote)
	if e == nil && (u.Scheme == "ssh" || u.Scheme == "https") && u.Host != "" && u.User == nil && u.Fragment == "" {
		return nil
	}
	// SSH user names are normal transport data; passwords never belong in an ad.
	if e == nil && u.Scheme == "ssh" && u.Host != "" && u.Fragment == "" && u.User != nil {
		if _, password := u.User.Password(); !password {
			return nil
		}
	}
	// SCP-style SSH locations are data as well; reject aliases containing shell
	// punctuation or path separators in the user/host part.
	if !strings.Contains(remote, "://") {
		host, path, ok := strings.Cut(remote, ":")
		if ok && host != "" && path != "" && strings.Count(host, "@") <= 1 && !strings.ContainsAny(host, "/\\ \t") {
			safe := true
			for _, c := range host {
				if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("@._-[]", c)) {
					safe = false
				}
			}
			if safe && !strings.HasSuffix(host, "@") {
				return nil
			}
		}
	}
	if file && ((e == nil && u.Scheme == "file" && (u.Host == "" || u.Host == "localhost")) || filepath.IsAbs(remote)) {
		return nil
	}
	return fail("directory_transport")
}

func directoryProtocols(environment []string) (map[string]bool, bool) {
	raw := ""
	explicit := false
	for _, entry := range environment {
		if strings.HasPrefix(entry, "GIT_ALLOW_PROTOCOL=") {
			raw = strings.TrimPrefix(entry, "GIT_ALLOW_PROTOCOL=")
			explicit = true
		}
	}
	requested := map[string]bool{}
	for _, p := range strings.Split(raw, ":") {
		requested[p] = true
	}
	return requested, explicit
}
func directoryFileAllowed(environment []string) bool {
	requested, explicit := directoryProtocols(environment)
	return explicit && requested["file"]
}

// DirectoryEnvironment returns a detached caller environment restricted to the
// discovery transport allowlist, including after Git insteadOf rewriting. Only
// explicit file opt-in survives; per-transport Git configuration cannot add one.
// A stricter explicit caller protocol list is preserved.
func DirectoryEnvironment(environment []string) []string {
	out := []string{}
	for _, entry := range environment {
		if !strings.HasPrefix(entry, "GIT_ALLOW_PROTOCOL=") {
			out = append(out, entry)
		}
	}
	requested, explicit := directoryProtocols(environment)
	allowed := []string{}
	for _, protocol := range []string{"ssh", "https", "file"} {
		if explicit && requested[protocol] || !explicit && protocol != "file" {
			allowed = append(allowed, protocol)
		}
	}
	return append(out, "GIT_ALLOW_PROTOCOL="+strings.Join(allowed, ":"))
}

func CloneDirectory(ctx context.Context, g Git, remote, branch string) error {
	if e := DirectoryRemote(remote, g.Environment); e != nil {
		return e
	}
	if g.Environment == nil || !safeBranch(branch) {
		return fail("invalid_configuration")
	}
	g.Environment = DirectoryEnvironment(g.Environment)
	directory := g.Directory
	g.Directory = filepath.Dir(directory)
	// Store conservative defaults as well; DirectoryEnvironment enforces the
	// allowlist independently of any per-protocol configuration.
	args := []string{"-c", "protocol.allow=never", "-c", "protocol.ssh.allow=always", "-c", "protocol.https.allow=always"}
	if directoryFileAllowed(g.Environment) {
		args = append(args, "-c", "protocol.file.allow=always")
	}
	args = append(args, "clone", "--no-tags", "--branch", branch, "--", remote, filepath.Base(directory))
	if _, e := g.run(ctx, nil, args...); e != nil {
		return e
	}
	g.Directory = directory
	for _, setting := range [][2]string{{"protocol.allow", "never"}, {"protocol.ssh.allow", "always"}, {"protocol.https.allow", "always"}} {
		if _, e := g.run(ctx, nil, "config", "--local", setting[0], setting[1]); e != nil {
			return e
		}
	}
	return nil
}
