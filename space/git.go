package space

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/relux-works/swarma-memory/kernel"
	"github.com/relux-works/swarma-memory/sign"
)

// Git takes its complete environment from the caller; it discovers no credentials
// and adds no environment variables. UnsignedCommits is an explicit test-only opt-in.
type Git struct {
	Directory       string
	Environment     []string
	UnsignedCommits bool
}

func (g Git) run(ctx context.Context, input []byte, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = g.Directory
	cmd.Env = g.Environment
	cmd.Stdin = bytes.NewReader(input)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, &Error{Code: "git_failed", Command: args[0]}
	}
	return stdout.Bytes(), nil
}

// Error contains only fixed diagnostic codes, never git stderr or record content.
type Error struct {
	Code    string
	Command string
}

func (e *Error) Error() string { return e.Code }
func fail(code string) error   { return &Error{Code: code} }
func errorCode(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	var d *sign.Diagnostic
	if errors.As(err, &d) {
		return string(d.Code)
	}
	return "invalid_transaction"
}

// Config supplies the trusted genesis anchor and the complete kernel configuration.
// Template has no records and includes independently authenticated intake reviews,
// lineage, grants, representations and domain metadata. Git never supplies them.
// CacheDirectory must be outside the space repository and private to this caller.
type Config struct {
	Git            Git
	Branch         string
	CacheDirectory string
	GenesisDigest  string
	Template       map[string]any
	Schemas        *kernel.Schemas
	Mint           func() (string, error)
	// Profile is independently trusted application code. It derives kernel
	// configuration from a verified in-force policy, never from local grants.
	Profile func(snapshot map[string]any, policy *VerifiedPolicy, operation map[string]any) (map[string]any, []any, error)
}

type Diagnostic struct {
	Commit string `json:"commit"`
	Path   string `json:"path"`
	Code   string `json:"code"`
}
type index struct {
	Cursor      string         `json:"cursor"`
	Snapshot    map[string]any `json:"snapshot"`
	Diagnostics []Diagnostic   `json:"diagnostics"`
}

// Repository serializes operations on one caller-owned clean working clone.
// Separate Repository values must not share a working clone or cache directory.
type Repository struct {
	mu      sync.Mutex
	config  Config
	current *index
	policy  *VerifiedPolicy
	state   *kernel.State
}

func Open(config Config) (*Repository, error) {
	if config.Branch == "" {
		config.Branch = "main"
	}
	if config.Git.Environment == nil || !safeBranch(config.Branch) || config.Schemas == nil || config.Mint == nil || !validDigest(config.GenesisDigest) {
		return nil, fail("invalid_configuration")
	}
	directory, e := filepath.Abs(config.Git.Directory)
	if e != nil {
		return nil, fail("invalid_configuration")
	}
	cache, e := filepath.Abs(config.CacheDirectory)
	if e != nil || config.CacheDirectory == "" {
		return nil, fail("invalid_configuration")
	}
	// Resolve existing parents as well: a cache symlink inside the clone must not
	// bypass the outside-repository contract.
	resolved, e := filepath.EvalSymlinks(directory)
	if e != nil {
		return nil, fail("invalid_configuration")
	}
	directory = resolved
	config.Git.Directory = directory
	rootBytes, gitError := config.Git.run(context.Background(), nil, "rev-parse", "--show-toplevel")
	if gitError != nil {
		return nil, gitError
	}
	root, rootError := filepath.EvalSymlinks(strings.TrimSpace(string(rootBytes)))
	if rootError != nil || root != directory {
		return nil, fail("invalid_configuration")
	}
	candidate := cache
	tail := []string{}
	for {
		resolvedParent, err := filepath.EvalSymlinks(candidate)
		if err == nil {
			for i := len(tail) - 1; i >= 0; i-- {
				resolvedParent = filepath.Join(resolvedParent, tail[i])
			}
			cache = resolvedParent
			break
		}
		if !errors.Is(err, os.ErrNotExist) {
			return nil, fail("cache_io")
		}
		tail = append(tail, filepath.Base(candidate))
		parent := filepath.Dir(candidate)
		if parent == candidate {
			return nil, fail("cache_io")
		}
		candidate = parent
	}
	relative, e := filepath.Rel(directory, cache)
	if e != nil || relative == "." || relative != ".." && !strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
		return nil, fail("cache_inside_repository")
	}
	if e = os.MkdirAll(cache, 0700); e != nil {
		return nil, fail("cache_io")
	}
	cache, e = filepath.EvalSymlinks(cache)
	if e != nil {
		return nil, fail("cache_io")
	}
	relative, e = filepath.Rel(directory, cache)
	if e != nil || relative == "." || relative != ".." && !strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
		return nil, fail("cache_inside_repository")
	}
	records, ok := config.Template["records"].([]any)
	if !ok || len(records) != 0 {
		return nil, fail("invalid_template")
	}
	encoded, r := kernel.CanonicalJSON(config.Template)
	if r != nil {
		return nil, r
	}
	detached, _ := kernel.DecodeJSON(encoded)
	config.Template = detached.(map[string]any)
	config.Git.Directory = directory
	config.Git.Environment = append([]string{}, config.Git.Environment...)
	config.CacheDirectory = cache
	repo := &Repository{config: config}
	b, e := os.ReadFile(filepath.Join(cache, "index.json"))
	if errors.Is(e, os.ErrNotExist) {
		return repo, nil
	}
	if e != nil {
		return nil, fail("cache_io")
	}
	value, r := kernel.DecodeJSON(b)
	if r != nil {
		return nil, fail("invalid_cache")
	}
	m, ok := value.(map[string]any)
	if !ok {
		return nil, fail("invalid_cache")
	}
	cursor, ok := m["cursor"].(string)
	if !ok || !objectID(cursor) {
		return nil, fail("invalid_cache")
	}
	// Only the pinned cursor is used. Rebuild even a present index from git objects;
	// corrupt or stale cached record/config bytes cannot inject admitted records.
	rebuilt, p, state, e := repo.replay(context.Background(), cursor)
	if e != nil {
		return nil, e
	}
	repo.current = rebuilt
	repo.policy = p
	repo.state = state
	return repo, nil
}
func safeBranch(s string) bool {
	if s == "" || strings.HasPrefix(s, "-") || strings.Contains(s, "..") || strings.Contains(s, "@{") || strings.HasSuffix(s, ".") || strings.HasSuffix(s, "/") {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("/_-.", c)) {
			return false
		}
	}
	return true
}
func objectID(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'f' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}
func (r *Repository) git(ctx context.Context, input []byte, args ...string) ([]byte, error) {
	return r.config.Git.run(ctx, input, args...)
}
func (r *Repository) Cursor() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.current == nil {
		return ""
	}
	return r.current.Cursor
}
func (r *Repository) Diagnostics() []Diagnostic {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.current == nil {
		return nil
	}
	return append([]Diagnostic{}, r.current.Diagnostics...)
}
func (r *Repository) Snapshot() map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.state == nil {
		return nil
	}
	return r.state.Snapshot()
}

// Sync also aligns a clean checkout with the verified cursor. Dirty caller work
// is preserved; Write rejects it before taking ownership of any paths.
func (r *Repository) Sync(ctx context.Context) (err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		if e := r.checkoutVerified(cleanup, false); e != nil {
			err = e
		}
	}()
	return r.sync(ctx)
}
func (r *Repository) sync(ctx context.Context) error {
	if _, e := r.git(ctx, nil, "fetch", "--no-tags", "origin", "+refs/heads/"+r.config.Branch+":refs/remotes/origin/"+r.config.Branch); e != nil {
		return e
	}
	b, e := r.git(ctx, nil, "rev-parse", "refs/remotes/origin/"+r.config.Branch)
	if e != nil {
		return e
	}
	head := strings.TrimSpace(string(b))
	if !objectID(head) {
		return fail("invalid_history")
	}
	if r.current != nil {
		b, e = r.git(ctx, nil, "rev-list", "--first-parent", head)
		if e != nil {
			return e
		}
		found := false
		for _, id := range strings.Fields(string(b)) {
			if id == r.current.Cursor {
				found = true
				break
			}
		}
		if !found {
			return fail("history_rewritten")
		}
	}
	rebuilt, p, state, e := r.replay(ctx, head)
	if e != nil {
		return e
	}
	if e = r.save(rebuilt); e != nil {
		return e
	}
	r.current = rebuilt
	r.policy = p
	r.state = state
	return nil
}
func (r *Repository) save(i *index) error {
	b, e := encode(i)
	if e != nil {
		return e
	}
	f, e := os.CreateTemp(r.config.CacheDirectory, ".index-*")
	if e != nil {
		return fail("cache_io")
	}
	name := f.Name()
	defer os.Remove(name)
	if _, e = f.Write(b); e == nil {
		e = f.Sync()
	}
	closeError := f.Close()
	if e == nil {
		e = closeError
	}
	if e != nil {
		return fail("cache_io")
	}
	if e = os.Rename(name, filepath.Join(r.config.CacheDirectory, "index.json")); e != nil {
		return fail("cache_io")
	}
	return nil
}
