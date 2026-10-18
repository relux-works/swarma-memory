package space

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/relux-works/swarma-memory/kernel"
	"github.com/relux-works/swarma-memory/scan"
	"github.com/relux-works/swarma-memory/sign"
)

// ScanError carries only the scanner's redacted findings.
type ScanError struct{ Findings []scan.Finding }

func (e *ScanError) Error() string { return "scan_refused" }

// WriteRequest builds once after sync. Retries keep that exact intent (especially
// expected_version); successful re-admission produces new canonical stamps before
// scanning and signing again. MaxRetries bounds additional push attempts.
type WriteRequest struct {
	Build      func(snapshot map[string]any) (map[string]any, error)
	Signer     sign.WriteSigner
	MaxRetries int
}
type WriteResult struct {
	Receipt      map[string]any
	Commit       string
	PushAttempts int
}

func (r *Repository) Write(ctx context.Context, request WriteRequest) (WriteResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var result WriteResult
	if request.Build == nil || request.Signer == nil || request.MaxRetries < 0 {
		return result, fail("invalid_request")
	}
	if e := r.sync(ctx); e != nil {
		return result, e
	}
	operation, e := request.Build(r.state.Snapshot())
	if e != nil {
		return result, e
	}
	if f := r.config.Schemas.ValidateWriteOperation(operation); f != nil {
		return result, f
	}
	operation = detached(operation)
	for attempt := 0; ; attempt++ {
		oldHead := r.current.Cursor
		candidate, f := r.state.Fork(r.config.Mint)
		if f != nil {
			return result, f
		}
		if e := r.configure(candidate, r.policy, operation); e != nil {
			return result, e
		}
		before := len(candidate.Snapshot()["records"].([]any))
		receipt, f := candidate.Write(operation)
		if f != nil {
			if f.Code == kernel.DuplicateRecord {
				return result, fail("version_conflict")
			}
			return result, fail(string(f.Code))
		}
		records := candidate.Snapshot()["records"].([]any)[before:]
		if len(records) == 0 {
			result.Receipt = receipt
			result.Commit = r.current.Cursor
			return result, nil
		}
		// Metadata is persisted alongside the signed outputs too. Scan it before
		// asking for any signature; do not let an idempotency key carry a secret.
		limits := r.policy.policy.Limits
		metadata := map[string]any{"context": operation["context"], "idempotency_key": operation["idempotency_key"]}
		findings := scan.Scan(metadata, scan.Limits{MaxCanonicalBytes: int(limits.MaxRecordBytes), MaxStringBytes: int(limits.MaxFieldBytes), MaxArrayLength: int(limits.MaxRecordBytes)})
		if len(findings) != 0 {
			return result, &ScanError{findings}
		}
		signed := []any{}
		files := map[string][]byte{}
		domains := r.config.Template["domain_schemas"].([]any)
		for _, value := range records {
			record, e := sign.NewCanonicalRecord(value, r.config.Schemas, domains)
			if e != nil {
				return result, e
			}
			if _, e = r.policy.checkRecord(record, r.config.Schemas, domains); e != nil {
				return result, e
			}
			findings := scan.Scan(value, scan.Limits{MaxCanonicalBytes: int(limits.MaxRecordBytes), MaxStringBytes: int(limits.MaxFieldBytes), MaxArrayLength: int(limits.MaxRecordBytes)})
			if len(findings) != 0 {
				return result, &ScanError{findings}
			}
			signature, e := request.Signer.Sign(record)
			if e != nil {
				return result, e
			}
			s := sign.SignedRecord{Record: record, Signature: signature}
			if _, e = r.policy.VerifyRecord(s, r.config.Schemas, domains); e != nil {
				return result, e
			}
			b, e := encode(s)
			if e != nil {
				return result, e
			}
			v, _ := kernel.DecodeJSON(b)
			signed = append(signed, v)
			files[RecordPath(record)] = b
		}
		tree, e := r.writeTree(ctx, oldHead, files)
		if e != nil {
			return result, e
		}
		origin := map[string]any{"space": r.policy.policy.SpaceID, "parent": oldHead, "tree": tree, "policy": r.policy.Digest()}
		value := map[string]any{"operation": operation, "records": signed, "receipt_handle": receipt["receipt_handle"], "origin": origin}
		canonical, e := sign.NewCanonicalWrite(value, r.config.Schemas, domains)
		if e != nil {
			return result, e
		}
		signature, e := request.Signer.SignWrite(canonical)
		if e != nil {
			return result, e
		}
		tx := transaction{value, signature}
		// Check the signed transaction and its exact output before touching the clone.
		valid := map[string]sign.SignedRecord{}
		for path, b := range files {
			s, e := sign.ParseRecord(b, r.config.Schemas, domains)
			if e != nil {
				return result, e
			}
			valid[path] = s
		}
		if _, e = r.applyTransaction(r.state, r.policy, tx, oldHead, tree, valid, map[string]bool{}); e != nil {
			return result, e
		}
		commit, e := r.commit(ctx, oldHead, files, []transaction{tx})
		if e != nil {
			return result, e
		}
		result.Commit = commit
		result.PushAttempts++
		_, pushError := r.git(ctx, nil, "push", "--porcelain", "origin", "HEAD:refs/heads/"+r.config.Branch)
		if pushError == nil {
			if e = r.sync(ctx); e != nil {
				return result, e
			}
			result.Receipt = receipt
			return result, nil
		}
		// Fetch also when the budget is exhausted: report a changed CAS token with
		// its specific refusal and retain the winner in the verified local view.
		if e = r.sync(ctx); e != nil {
			return result, e
		}
		check, f := r.state.Fork(r.config.Mint)
		if f != nil {
			return result, f
		}
		if e := r.configure(check, r.policy, operation); e != nil {
			return result, e
		}
		checkReceipt, f := check.Write(operation)
		if f != nil {
			if f.Code == kernel.DuplicateRecord {
				return result, fail("version_conflict")
			}
			return result, fail(string(f.Code))
		}
		if f == nil && len(check.Snapshot()["records"].([]any)) == len(r.state.Snapshot()["records"].([]any)) {
			result.Receipt = checkReceipt
			result.Commit = r.current.Cursor
			return result, nil
		}
		if r.current.Cursor == oldHead {
			return result, pushError
		}
		if attempt >= request.MaxRetries {
			return result, fail("retry_exhausted")
		}
	}
}
func (r *Repository) commit(ctx context.Context, head string, files map[string][]byte, txs []transaction) (string, error) {
	b, e := r.git(ctx, nil, "status", "--porcelain", "--untracked-files=all")
	if e != nil {
		return "", e
	}
	if len(b) != 0 {
		return "", fail("dirty_clone")
	}
	if _, e = r.git(ctx, nil, "switch", "--detach", head); e != nil {
		return "", e
	}
	paths := []string{}
	committed := false
	defer func() {
		if !committed && len(paths) > 0 {
			args := append([]string{"restore", "--staged", "--"}, paths...)
			_, _ = r.git(ctx, nil, args...)
			for _, path := range paths {
				_ = os.Remove(filepath.Join(r.config.Git.Directory, path))
			}
		}
	}()
	for path, data := range files {
		if !strings.HasPrefix(path, "records/") {
			return "", fail("invalid_path")
		}
		parent := r.config.Git.Directory
		parts := strings.Split(path, "/")
		for _, part := range parts[:len(parts)-1] {
			parent = filepath.Join(parent, part)
			info, e := os.Lstat(parent)
			if errors.Is(e, os.ErrNotExist) {
				if e = os.Mkdir(parent, 0755); e != nil {
					return "", fail("record_io")
				}
			} else if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return "", fail("invalid_path")
			}
		}
		f, e := os.OpenFile(filepath.Join(r.config.Git.Directory, path), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
		if e != nil {
			return "", fail("version_conflict")
		}
		paths = append(paths, path)
		_, e = f.Write(data)
		closeError := f.Close()
		if e != nil || closeError != nil {
			return "", fail("record_io")
		}
	}
	args := append([]string{"add", "--"}, paths...)
	if _, e = r.git(ctx, nil, args...); e != nil {
		return "", e
	}
	stagedTree, e := r.git(ctx, nil, "write-tree")
	if e != nil {
		return "", e
	}
	for _, tx := range txs {
		origin, _ := tx.Write["origin"].(map[string]any)
		if origin["parent"] != head || origin["tree"] != strings.TrimSpace(string(stagedTree)) {
			return "", fail("transaction_origin_mismatch")
		}
	}
	message, e := encode(txs)
	if e != nil {
		return "", e
	}
	args = []string{"commit", "-S", "--file=-"}
	if r.config.Git.UnsignedCommits {
		args = []string{"-c", "commit.gpgsign=false", "commit", "--file=-"}
	}
	if _, e = r.git(ctx, append([]byte(transactionPrefix), message...), args...); e != nil {
		return "", e
	}
	committed = true
	b, e = r.git(ctx, nil, "rev-parse", "HEAD")
	if e != nil {
		return "", e
	}
	head = strings.TrimSpace(string(b))
	if !r.config.Git.UnsignedCommits {
		if _, e = r.git(ctx, nil, "verify-commit", head); e != nil {
			return "", e
		}
	}
	return head, nil
}

// Clone creates a working clone using exactly the explicit caller environment.
// The caller chooses and authenticates the remote; this function reads no keys.
func Clone(ctx context.Context, git Git, remote, branch string) error {
	if git.Environment == nil || !safeBranch(branch) || remote == "" {
		return fail("invalid_configuration")
	}
	directory := git.Directory
	git.Directory = filepath.Dir(directory)
	_, e := git.run(ctx, nil, "clone", "--no-tags", "--branch", branch, "--", remote, filepath.Base(directory))
	return e
}
