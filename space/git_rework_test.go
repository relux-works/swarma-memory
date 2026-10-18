package space_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/swarma-memory/kernel"
	"github.com/relux-works/swarma-memory/sign"
	"github.com/relux-works/swarma-memory/space"
)

func transactionCopy(t *testing.T, tx map[string]any) map[string]any {
	t.Helper()
	v, refusal := kernel.DecodeJSON(jsonBytes(t, tx))
	if refusal != nil {
		t.Fatal(refusal)
	}
	return v.(map[string]any)
}

func transactionBytes(t *testing.T, tx map[string]any) []byte {
	t.Helper()
	b, refusal := kernel.CanonicalJSON(transactionCopy(t, tx))
	if refusal != nil {
		t.Fatal(refusal)
	}
	return b
}

func resignTransaction(t *testing.T, h *gitHarness, tx map[string]any) {
	t.Helper()
	w, e := sign.NewCanonicalWrite(tx["write"].(map[string]any), h.f.schemas, h.template["domain_schemas"].([]any))
	check(t, e)
	sig, e := h.f.writer.SignWrite(w)
	check(t, e)
	tx["signature"] = sig
}

// An unchanged signed transaction from an unmerged source commit is refused at
// a different tree, including the same parent and a later owner-signed policy.
// A correctly bound neighbour in the destination commit still admits.
func TestGitTransactionOriginTransplant(t *testing.T) {
	for _, changePolicy := range []bool{false, true} {
		name := "other_source_commit"
		if changePolicy {
			name = "after_other_policy"
		}
		t.Run(name, func(t *testing.T) {
			h := newGitHarness(t)
			r, _, _ := h.clone(t, "reader")
			check(t, r.Sync(context.Background()))
			files, bad := h.transactionFiles(t, r.Snapshot(), h.op(t, "rec:bad", h.f.writer.Identity()), h.f.writer)
			gitCommand(t, h.seed, h.env, "switch", "-c", "source")
			bindTransactions(t, h, h.seed, files, h.f.policy, bad)
			source := rawCommit(t, h, h.seed, files, []map[string]any{bad})
			original := jsonBytes(t, bad)
			gitCommand(t, h.seed, h.env, "switch", "--detach", h.genesis)
			policy := h.f.policy
			if changePolicy {
				policy = nextPolicy(t, h, policy, func(p *space.Policy) { p.Retention.OnOwnerRetire = "retain" })
				rawCommit(t, h, h.seed, map[string][]byte{"space.json": jsonBytes(t, policy)}, nil)
			}
			gf, good := h.transactionFiles(t, r.Snapshot(), h.op(t, "rec:good", h.f.writer.Identity()), h.f.writer)
			for path, data := range gf {
				files[path] = data
			}
			bindTransactions(t, h, h.seed, files, policy, good) // Never rebind the transplant.
			destination := rawCommit(t, h, h.seed, files, []map[string]any{bad, good})
			if destination == source || !bytes.Equal(original, jsonBytes(t, bad)) {
				t.Fatal("witness did not preserve the exact source transaction")
			}
			h.push(t, h.seed)
			check(t, r.Sync(context.Background()))
			assertGoodOnly(t, h, r)
			expectDiagnostic(t, r, "transaction_origin_mismatch")
		})
	}
}

// These independently signed variants isolate each context check: the proposed
// tree is correct while the parent, space or in-force policy digest is wrong.
// Altering a context without re-signing instead fails cryptographic verification.
func TestGitTransactionOriginFields(t *testing.T) {
	for _, field := range []string{"parent", "space", "policy", "unsigned_change"} {
		t.Run(field, func(t *testing.T) {
			h := newGitHarness(t)
			r, _, _ := h.clone(t, "reader")
			check(t, r.Sync(context.Background()))
			policy := nextPolicy(t, h, h.f.policy, func(p *space.Policy) { p.Limits.MaxFieldBytes++ })
			rawCommit(t, h, h.seed, map[string][]byte{"space.json": jsonBytes(t, policy)}, nil)
			files, bad := h.transactionFiles(t, r.Snapshot(), h.op(t, "rec:bad", h.f.writer.Identity()), h.f.writer)
			gf, good := h.transactionFiles(t, r.Snapshot(), h.op(t, "rec:good", h.f.writer.Identity()), h.f.writer)
			for path, data := range gf {
				files[path] = data
			}
			bindTransactions(t, h, h.seed, files, policy, bad, good)
			origin := bad["write"].(map[string]any)["origin"].(map[string]any)
			expected := "transaction_origin_mismatch"
			switch field {
			case "parent":
				origin["parent"] = h.genesis
			case "space":
				origin["space"] = "space:unrelated"
			case "policy":
				origin["policy"] = h.f.anchor
				expected = "transaction_policy_mismatch"
			case "unsigned_change":
				origin["tree"] = strings.Repeat("a", 40)
				expected = "invalid_signature"
			}
			if field != "unsigned_change" {
				resignTransaction(t, h, bad)
			}
			rawCommit(t, h, h.seed, files, []map[string]any{bad, good})
			h.push(t, h.seed)
			check(t, r.Sync(context.Background()))
			expectDiagnostic(t, r, expected)
			assertGoodOnly(t, h, r)
		})
	}
}

func assertGoodOnly(t *testing.T, h *gitHarness, r *space.Repository) {
	t.Helper()
	records := r.Snapshot()["records"].([]any)
	if len(records) != 1 || records[0].(map[string]any)["envelope"].(map[string]any)["id"] != "rec:good" {
		t.Fatalf("transplant admitted or neighbour lost: %+v diagnostics=%+v", records, r.Diagnostics())
	}
	view, e := r.Read(h.readQuery(t, r, h.f.writer.Identity()))
	check(t, e)
	if len(view["items"].([]any)) != 1 {
		t.Fatal("rejected evidence influenced the read view")
	}
}

// Preserve the reviewer's overlap witness: a correctly signed stale-generation
// transaction orders before a valid one sharing the exact signed output. Neither
// that refusal nor a post-admission output mismatch may reserve the shared path.
// A valid-only neighbouring control proves this fixture can admit both files.
func TestGitRejectedTransactionDoesNotPoison(t *testing.T) {
	for _, kind := range []string{"stale_generation", "output_mismatch", "valid_only"} {
		t.Run(kind, func(t *testing.T) {
			h := newGitHarness(t)
			r, _, _ := h.clone(t, "reader")
			check(t, r.Sync(context.Background()))
			files, valid := h.transactionFiles(t, r.Snapshot(), h.op(t, "rec:bad", h.f.writer.Identity()), h.f.writer)
			gf, good := h.transactionFiles(t, r.Snapshot(), h.op(t, "rec:good", h.f.writer.Identity()), h.f.writer)
			for path, data := range gf {
				files[path] = data
			}
			bindTransactions(t, h, h.seed, files, h.f.policy, valid, good)
			txs := []map[string]any{valid, good}
			if kind != "valid_only" {
				var invalid map[string]any
				for i := 0; i < 1000; i++ {
					// Resample both signatures: a fixed valid signature near the
					// minimum would give a flaky bounded ordering search.
					valid["write"].(map[string]any)["receipt_handle"], _ = randomHandle()
					resignTransaction(t, h, valid)
					bad := transactionCopy(t, valid)
					write := bad["write"].(map[string]any)
					op := write["operation"].(map[string]any)
					if kind == "stale_generation" {
						op["expected_generation"] = int64(99)
					} else {
						op["proposals"].([]any)[0].(map[string]any)["body"].(map[string]any)["content"].([]any)[0].(map[string]any)["value"] = "inconsistent output"
					}
					write["receipt_handle"], _ = randomHandle()
					resignTransaction(t, h, bad)
					if bytes.Compare(transactionBytes(t, bad), transactionBytes(t, valid)) < 0 {
						invalid = bad
						break
					}
				}
				if invalid == nil {
					t.Fatal("could not order signed refusal before the valid transaction")
				}
				txs = append(txs, invalid)
			}
			rawCommit(t, h, h.seed, files, txs)
			h.push(t, h.seed)
			check(t, r.Sync(context.Background()))
			switch kind {
			case "stale_generation":
				expectDiagnostic(t, r, "stale_generation")
			case "output_mismatch":
				expectDiagnostic(t, r, "admission_output_mismatch")
			case "valid_only":
				if len(r.Diagnostics()) != 0 {
					t.Fatal(r.Diagnostics())
				}
			}
			for _, d := range r.Diagnostics() {
				if d.Code == "transaction_file_mismatch" || d.Code == "missing_transaction" {
					t.Fatalf("refusal poisoned output eligibility: %+v", r.Diagnostics())
				}
			}
			if len(r.Snapshot()["records"].([]any)) != 2 {
				t.Fatalf("valid transaction suppressed: %+v", r.Diagnostics())
			}
		})
	}
}

// Closed origin parsing rejects missing, extra, ill-typed and malformed fields;
// these are wire checks only, paired with a complete valid signed payload.
func TestWriteOriginShape(t *testing.T) {
	h := newGitHarness(t)
	_, tx := h.transactionFiles(t, h.template, h.op(t, "rec:a", h.f.writer.Identity()), h.f.writer)
	w := tx["write"].(map[string]any)
	_, e := sign.NewCanonicalWrite(w, h.f.schemas, h.template["domain_schemas"].([]any))
	check(t, e)
	for _, kind := range []string{"missing", "not_object", "extra", "space", "parent", "tree", "policy", "missing_parent"} {
		t.Run(kind, func(t *testing.T) {
			bad := mapCopy(t, w)
			origin := bad["origin"].(map[string]any)
			switch kind {
			case "missing":
				delete(bad, "origin")
			case "not_object":
				bad["origin"] = "untrusted"
			case "extra":
				origin["extra"] = true
			case "space":
				origin["space"] = int64(1)
			case "parent":
				origin["parent"] = strings.Repeat("A", 40)
			case "tree":
				origin["tree"] = strings.Repeat("a", 64)
			case "policy":
				origin["policy"] = strings.Repeat("a", 64)
			case "missing_parent":
				delete(origin, "parent")
			}
			_, e := sign.NewCanonicalWrite(bad, h.f.schemas, h.template["domain_schemas"].([]any))
			diagnostic(t, e, sign.InvalidShape)
		})
	}
}

// Git independently checks the proposed tree at commit time for both object
// formats. Existing nested paths, executable modes and symlinks survive intact.
func TestGitOriginTreeMatchesGit(t *testing.T) {
	for _, format := range []string{"sha1", "sha256"} {
		t.Run(format, func(t *testing.T) {
			h := newGitHarnessFormat(t, format)
			for _, path := range []string{"records.extra", "records-aux/nested/file", "records-aux.txt"} {
				putFile(t, h.seed, path, []byte("synthetic fixture\n"))
			}
			check(t, os.Chmod(filepath.Join(h.seed, "records.extra"), 0755))
			check(t, os.Symlink("synthetic-target", filepath.Join(h.seed, "z-link")))
			gitCommand(t, h.seed, h.env, "add", "--", "records.extra", "records-aux", "records-aux.txt", "z-link")
			gitCommand(t, h.seed, h.env, "commit", "-m", "Tree format controls")
			h.push(t, h.seed)
			r, dir, _ := h.clone(t, "writer")
			result := mustWrite(t, r, h.op(t, "rec:a", h.f.writer.Identity()), h.f.writer)
			message := gitCommand(t, dir, h.env, "show", "-s", "--format=%B", result.Commit)
			v, refusal := kernel.DecodeJSON([]byte(strings.TrimPrefix(message, writeMessagePrefix)))
			if refusal != nil {
				t.Fatal(refusal)
			}
			origin := v.([]any)[0].(map[string]any)["write"].(map[string]any)["origin"].(map[string]any)
			if origin["tree"] != gitCommand(t, dir, h.env, "rev-parse", "HEAD^{tree}") {
				t.Fatal("tree binding differs from Git")
			}
			if len(r.Snapshot()["records"].([]any)) != 1 {
				t.Fatal("valid output excluded")
			}
			for _, d := range r.Diagnostics() {
				if strings.HasPrefix(d.Code, "transaction_") {
					t.Fatal(d)
				}
			}
		})
	}
}

// A newly reachable metadata-only side commit cannot authorize a signed file
// first added by the merge. A normal first-parent neighbour remains admitted.
func TestGitMetadataCarrierCannotIntroduceOutputs(t *testing.T) {
	h := newGitHarness(t)
	r, dir, _ := h.clone(t, "reader")
	check(t, r.Sync(context.Background()))
	files, tx := h.transactionFiles(t, r.Snapshot(), h.op(t, "rec:bad", h.f.writer.Identity()), h.f.writer)
	gitCommand(t, h.seed, h.env, "switch", "-c", "carrier")
	// initialOrigin is the actual parent/tree of this empty metadata commit.
	gitCommand(t, h.seed, h.env, "commit", "--allow-empty", "-m", writeMessagePrefix+string(jsonBytes(t, []any{tx})))
	carrier := gitCommand(t, h.seed, h.env, "rev-parse", "HEAD")
	mustWrite(t, r, h.op(t, "rec:good", h.f.writer.Identity()), h.f.writer)
	gitCommand(t, dir, h.env, "fetch", h.seed, carrier)
	gitCommand(t, dir, h.env, "merge", "--no-ff", "--no-commit", "FETCH_HEAD")
	for path, data := range files {
		putFile(t, dir, path, data)
		gitCommand(t, dir, h.env, "add", "--", path)
	}
	gitCommand(t, dir, h.env, "commit", "-m", "Merge metadata carrier with extra output")
	h.push(t, dir)
	check(t, r.Sync(context.Background()))
	expectDiagnostic(t, r, "transaction_origin_mismatch")
	assertGoodOnly(t, h, r)
}
