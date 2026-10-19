package space

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/relux-works/swarma-memory/go/sign"
)

// EndorsePolicy re-endorses every retained registration for this policy version,
// then signs the complete closed policy. It conveys no authority by itself.
func EndorsePolicy(p Policy, signer PolicySigner) (SignedPolicy, error) {
	if signer == nil {
		return SignedPolicy{}, fail("invalid_request")
	}
	p.Keys = append([]SignedRegistration{}, p.Keys...)
	for i := range p.Keys {
		r := p.Keys[i].Registration
		r.Author, r.PolicyVersion, r.SpaceID = p.Author, p.Version, p.SpaceID
		canonical, e := NewCanonicalRegistration(r)
		if e != nil {
			return SignedPolicy{}, e
		}
		sig, e := signer.SignRegistration(canonical)
		if e != nil {
			return SignedPolicy{}, e
		}
		p.Keys[i] = SignedRegistration{r, sig}
	}
	c, e := NewCanonicalPolicy(p)
	if e != nil {
		return SignedPolicy{}, e
	}
	sig, e := signer.SignPolicy(c)
	if e != nil {
		return SignedPolicy{}, e
	}
	return SignedPolicy{p, sig}, nil
}

// UpdatePolicy verifies the current owner's new version before changing the
// clone. A racing push refuses; it never overwrites or force-pushes another owner.
func (r *Repository) UpdatePolicy(ctx context.Context, author string, signer PolicySigner, change func(*Policy) error) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if signer == nil || change == nil {
		return "", fail("invalid_request")
	}
	if e := r.sync(ctx); e != nil {
		return "", e
	}
	if r.policy == nil || !has(r.policy.policy.Owners, author) {
		return "", sign.Fail(sign.UnauthorizedOwner, "author")
	}
	p := r.policy.Policy()
	previous := r.policy.Digest()
	p.Previous = &previous
	p.Version++
	p.Author = author
	if e := change(&p); e != nil {
		return "", e
	}
	signed, e := EndorsePolicy(p, signer)
	if e != nil {
		return "", e
	}
	if _, e = verifyNextPolicy(r.policy, signed, r.config.GenesisDigest); e != nil {
		return "", e
	}
	head, e := r.commitPolicy(ctx, signed, r.current.Cursor)
	if e == nil {
		e = r.sync(ctx)
	}
	return head, e
}

// InitializePolicy publishes only a valid self-signed genesis in an empty clone.
func InitializePolicy(ctx context.Context, git Git, branch string, signed SignedPolicy) (string, string, error) {
	canonical, e := NewCanonicalPolicy(signed.Policy)
	if e != nil {
		return "", "", e
	}
	digest := sign.PolicyDigest(canonical.Bytes())
	if _, e := VerifyChain([]SignedPolicy{signed}, digest); e != nil {
		return "", "", e
	}
	if git.Environment == nil || !safeBranch(branch) {
		return "", "", fail("invalid_configuration")
	}
	if b, e := git.run(ctx, nil, "rev-list", "--all"); e != nil || len(b) != 0 {
		return "", "", fail("nonempty_remote")
	}
	if _, e := git.run(ctx, nil, "symbolic-ref", "HEAD", "refs/heads/"+branch); e != nil {
		return "", "", e
	}
	r := &Repository{config: Config{Git: git, Branch: branch}}
	head, e := r.commitPolicy(ctx, signed, "")
	return head, digest, e
}

func (r *Repository) commitPolicy(ctx context.Context, policy SignedPolicy, parent string) (string, error) {
	b, e := r.git(ctx, nil, "status", "--porcelain", "--untracked-files=all")
	if e != nil {
		return "", e
	}
	if len(b) != 0 {
		return "", fail("dirty_clone")
	}
	if parent != "" {
		if _, e = r.git(ctx, nil, "switch", "--detach", parent); e != nil {
			return "", e
		}
	}
	path := filepath.Join(r.config.Git.Directory, "space.json")
	if info, e := os.Lstat(path); e == nil && (!info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0) {
		return "", fail("invalid_file_mode")
	}
	committed := false
	defer func() {
		if committed {
			return
		}
		if parent != "" {
			_, _ = r.git(ctx, nil, "restore", "--source="+parent, "--staged", "--worktree", "--", "space.json")
		} else {
			_, _ = r.git(ctx, nil, "rm", "--cached", "--ignore-unmatch", "--", "space.json")
			_ = os.Remove(path)
		}
	}()
	b, e = encode(policy)
	if e != nil {
		return "", e
	}
	if e = os.WriteFile(path, b, 0644); e != nil {
		return "", fail("policy_io")
	}
	if _, e = r.git(ctx, nil, "add", "--", "space.json"); e != nil {
		return "", e
	}
	if _, e = r.git(ctx, []byte("swarma-memory owner policy\n"), "commit", "-S", "--file=-"); e != nil {
		return "", e
	}
	committed = true
	b, e = r.git(ctx, nil, "rev-parse", "HEAD")
	if e != nil {
		return "", e
	}
	head := strings.TrimSpace(string(b))
	if _, e = r.git(ctx, nil, "verify-commit", head); e != nil {
		return "", e
	}
	if _, e = r.git(ctx, nil, "push", "--porcelain", "origin", "HEAD:refs/heads/"+r.config.Branch); e != nil {
		return "", fail("version_conflict")
	}
	return head, nil
}
