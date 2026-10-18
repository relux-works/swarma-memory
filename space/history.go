package space

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"
	"strings"

	"github.com/relux-works/swarma-memory/kernel"
	"github.com/relux-works/swarma-memory/sign"
)

const transactionPrefix = "swarma-memory transactions/1\n\n"

type transaction struct {
	Write     map[string]any `json:"write"`
	Signature sign.Signature `json:"signature"`
}

type introducedTransaction struct {
	transaction
	parent, tree string
}

func encode(value any) ([]byte, error) {
	b, e := json.Marshal(value)
	if e != nil {
		return nil, fail("invalid_json")
	}
	v, r := kernel.DecodeJSON(b)
	if r != nil {
		return nil, r
	}
	b, r = kernel.CanonicalJSON(v)
	if r != nil {
		return nil, r
	}
	return b, nil
}
func detached(m map[string]any) map[string]any {
	b, _ := kernel.CanonicalJSON(m)
	v, _ := kernel.DecodeJSON(b)
	out, _ := v.(map[string]any)
	return out
}

// RecordPath encodes opaque identifiers as lowercase hexadecimal to keep every component
// unambiguous and prevent traversal, case folding and slash aliases.
func RecordPath(record sign.CanonicalRecord) string {
	v := record.Value()
	e, _ := v["envelope"].(map[string]any)
	id, _ := e["id"].(string)
	kind, _ := e["kind"].(string)
	version, _ := e["version"].(int64)
	return "records/" + kind + "/" + hex.EncodeToString([]byte(id)) + "/" + strconv.FormatInt(version, 10) + ".json"
}

type treeEntry struct{ mode, blob string }

func (r *Repository) tree(ctx context.Context, commit string) (map[string]treeEntry, error) {
	return r.listTree(ctx, commit, false)
}

func (r *Repository) listTree(ctx context.Context, commit string, directories bool) (map[string]treeEntry, error) {
	flags := "-rz"
	if directories {
		flags = "-rzt"
	}
	b, e := r.git(ctx, nil, "ls-tree", flags, "--full-tree", commit)
	if e != nil {
		return nil, e
	}
	out := map[string]treeEntry{}
	for _, line := range bytes.Split(b, []byte{0}) {
		if len(line) == 0 {
			continue
		}
		parts := bytes.SplitN(line, []byte{'\t'}, 2)
		if len(parts) != 2 {
			return nil, fail("invalid_history")
		}
		meta := strings.Fields(string(parts[0]))
		if len(meta) != 3 {
			return nil, fail("invalid_history")
		}
		out[string(parts[1])] = treeEntry{meta[0], meta[2]}
	}
	return out, nil
}
func (r *Repository) blob(ctx context.Context, e treeEntry) ([]byte, error) {
	if e.mode != "100644" && e.mode != "100755" {
		return nil, fail("invalid_file_mode")
	}
	return r.git(ctx, nil, "cat-file", "blob", e.blob)
}
func (r *Repository) replay(ctx context.Context, head string) (*index, *VerifiedPolicy, *kernel.State, error) {
	return r.replayCapture(ctx, head, "", nil)
}
func (r *Repository) replayCapture(ctx context.Context, head, since string, query map[string]any) (*index, *VerifiedPolicy, *kernel.State, error) {
	b, e := r.git(ctx, nil, "rev-list", "--reverse", "--first-parent", head)
	if e != nil {
		return nil, nil, nil, e
	}
	state, refusal := kernel.NewState(r.config.Template, r.config.Schemas, r.config.Mint)
	if refusal != nil {
		return nil, nil, nil, refusal
	}
	diagnostics := []Diagnostic{}
	previous := map[string]treeEntry{}
	seen := map[string]bool{}
	chain := []SignedPolicy{}
	var policy *VerifiedPolicy
	domains, _ := r.config.Template["domain_schemas"].([]any)
	priorCommit := ""
	for _, commit := range strings.Fields(string(b)) {
		tree, e := r.tree(ctx, commit)
		if e != nil {
			return nil, nil, nil, e
		}
		diag := func(path string, e error) { diagnostics = append(diagnostics, Diagnostic{commit, path, errorCode(e)}) }
		if current, ok := tree["space.json"]; ok && current != previous["space.json"] {
			data, e := r.blob(ctx, current)
			if e == nil {
				var p SignedPolicy
				p, e = ParsePolicy(data)
				if e == nil {
					candidate := append(append([]SignedPolicy{}, chain...), p)
					var verified []*VerifiedPolicy
					verified, e = VerifyChain(candidate, r.config.GenesisDigest)
					if e == nil {
						chain = candidate
						policy = verified[len(verified)-1]
					}
				}
			}
			if e != nil {
				diag("space.json", e)
			}
		} else if _, ok := tree["space.json"]; !ok && previous["space.json"].blob != "" {
			diag("space.json", fail("immutable_policy"))
		}
		paths := []string{}
		for path, entry := range tree {
			if entry != previous[path] {
				paths = append(paths, path)
			}
		}
		for path := range previous {
			if _, ok := tree[path]; !ok {
				paths = append(paths, path)
			}
		}
		sort.Strings(paths)
		valid := map[string]sign.SignedRecord{}
		bound := map[string]bool{}
		for _, path := range paths {
			if path == "space.json" {
				continue
			}
			if strings.HasPrefix(path, "directory/") {
				if policy == nil || policy.policy.Kind != "platform" {
					diag(path, fail("directory_not_platform"))
				}
				continue
			}
			if !strings.HasPrefix(path, "records/") {
				diag(path, fail("invalid_layout"))
				continue
			}
			if seen[path] {
				diag(path, fail("record_rewritten"))
				continue
			}
			seen[path] = true
			entry, exists := tree[path]
			if !exists {
				diag(path, fail("record_rewritten"))
				continue
			}
			data, e := r.blob(ctx, entry)
			var signed sign.SignedRecord
			if e == nil {
				signed, e = sign.ParseRecord(data, r.config.Schemas, domains)
			}
			if e == nil && RecordPath(signed.Record) != path {
				e = fail("record_path_mismatch")
			}
			if e == nil {
				_, e = policy.VerifyRecord(signed, r.config.Schemas, domains)
			}
			if e != nil {
				diag(path, e)
				bound[path] = true
				continue
			}
			valid[path] = signed
		}
		// A merge introduces side-branch files at this first-parent position.
		// Their signed transaction metadata remains in the introducing side
		// commits, so inspect all newly reachable messages, never arrival order.
		args := []string{"rev-list", "--reverse", commit}
		if priorCommit != "" {
			args = append(args, "^"+priorCommit)
		}
		introduced, e := r.git(ctx, nil, args...)
		if e != nil {
			return nil, nil, nil, e
		}
		transactions := []introducedTransaction{}
		for _, sourceCommit := range strings.Fields(string(introduced)) {
			message, e := r.git(ctx, nil, "show", "-s", "--format=%B", sourceCommit)
			if e != nil {
				return nil, nil, nil, e
			}
			if !strings.HasPrefix(string(message), transactionPrefix) {
				continue
			}
			provenance, e := r.git(ctx, nil, "show", "-s", "--format=%P%n%T", sourceCommit)
			if e != nil {
				return nil, nil, nil, e
			}
			lines := strings.Split(strings.TrimSpace(string(provenance)), "\n")
			if len(lines) != 2 || len(strings.Fields(lines[0])) == 0 {
				diag("", fail("transaction_origin_mismatch"))
				continue
			}
			parent, sourceTree := strings.Fields(lines[0])[0], lines[1]
			txs, e := parseTransactions(bytes.TrimSpace(message[len(transactionPrefix):]))
			if e != nil {
				diag("", e)
			}
			for _, tx := range txs {
				// Skip transactions whose files are absent or already accounted for
				// on the mainline. They are not newly introduced evaluation inputs.
				records, _ := tx.Write["records"].([]any)
				relevant := false
				for _, record := range records {
					wire, _ := kernel.CanonicalJSON(record)
					signed, e := sign.ParseRecord(wire, r.config.Schemas, domains)
					if e == nil {
						if _, ok := valid[RecordPath(signed.Record)]; ok {
							relevant = true
						}
					}
				}
				if relevant {
					if e := r.verifySourceOutputs(ctx, tx, sourceCommit, parent, domains); e != nil {
						diag(transactionOrder(tx), e)
						continue
					}
					transactions = append(transactions, introducedTransaction{tx, parent, sourceTree})
				}
			}
		}
		sort.SliceStable(transactions, func(i, j int) bool {
			left, right := transactionOrder(transactions[i].transaction), transactionOrder(transactions[j].transaction)
			if left != right {
				return left < right
			}
			a, _ := encode(transactions[i].transaction)
			b, _ := encode(transactions[j].transaction)
			return bytes.Compare(a, b) < 0
		})
		type admittedIntent struct{ parent, tree, payload string }
		admitted := map[admittedIntent]bool{}
		for _, tx := range transactions {
			payload, e := encode(tx.transaction)
			if e != nil {
				diag(transactionOrder(tx.transaction), e)
				continue
			}
			intent := admittedIntent{tx.parent, tx.tree, string(payload)}
			// Distinct commits can carry the same authenticated intent. Only
			// successful admission at this position permits reuse; the actual
			// source parent/tree and the complete signed payload must match.
			// Each carrier's source outputs were independently checked above.
			if admitted[intent] {
				continue
			}
			next, e := r.applyTransaction(state, policy, tx.transaction, tx.parent, tx.tree, valid, bound)
			if e != nil {
				diag(transactionOrder(tx.transaction), e)
			} else {
				state = next
				admitted[intent] = true
			}
		}

		for _, path := range paths {
			if _, ok := valid[path]; ok && !bound[path] {
				diag(path, fail("missing_transaction"))
			}
		}
		if since == commit {
			q := detached(query)
			q["kind"] = "recall"
			q["since"] = nil
			q["cut"].(map[string]any)["memory"] = state.Snapshot()["runtime"].(map[string]any)["memory_cut"]
			if _, refusal := state.Capture(0, q); refusal != nil {
				return nil, nil, nil, fail(string(refusal.Code))
			}
		}
		previous = tree
		priorCommit = commit
	}
	if policy == nil {
		return nil, nil, nil, fail("no_verified_policy")
	}
	return &index{head, state.Snapshot(), diagnostics}, policy, state, nil
}

// An authenticated tree is meaningful only if it actually introduced the signed
// outputs. A metadata-only side commit cannot authorize files added elsewhere.
func (r *Repository) verifySourceOutputs(ctx context.Context, tx transaction, commit, parent string, domains []any) error {
	source, e := r.tree(ctx, commit)
	if e != nil {
		return e
	}
	previous, e := r.tree(ctx, parent)
	if e != nil {
		return e
	}
	records, _ := tx.Write["records"].([]any)
	for _, value := range records {
		wire, _ := kernel.CanonicalJSON(value)
		signed, e := sign.ParseRecord(wire, r.config.Schemas, domains)
		if e != nil {
			return e
		}
		path := RecordPath(signed.Record)
		entry, exists := source[path]
		if !exists || entry == previous[path] {
			return fail("transaction_origin_mismatch")
		}
		data, e := r.blob(ctx, entry)
		if e != nil {
			return e
		}
		stored, e := sign.ParseRecord(data, r.config.Schemas, domains)
		if e != nil {
			return e
		}
		canonical, _ := encode(stored)
		if !bytes.Equal(wire, canonical) {
			return fail("transaction_file_mismatch")
		}
	}
	return nil
}

func transactionOrder(tx transaction) string {
	rs, _ := tx.Write["records"].([]any)
	if len(rs) == 0 {
		return ""
	}
	s, _ := rs[0].(map[string]any)
	rec, _ := s["record"].(map[string]any)
	e, _ := rec["envelope"].(map[string]any)
	id, _ := e["id"].(string)
	version, _ := e["version"].(int64)
	kind, _ := e["kind"].(string)
	return "records/" + kind + "/" + hex.EncodeToString([]byte(id)) + "/" + strconv.FormatInt(version, 10) + ".json"
}
func parseTransactions(b []byte) ([]transaction, error) {
	v, refusal := kernel.DecodeJSON(b)
	if refusal != nil {
		return nil, fail("invalid_transaction")
	}
	a, ok := v.([]any)
	if !ok {
		return nil, fail("invalid_transaction")
	}
	out := make([]transaction, 0, len(a))
	var firstError error
	for _, x := range a {
		tx, e := parseTransaction(x)
		if e != nil {
			if firstError == nil {
				firstError = e
			}
			continue
		}
		out = append(out, tx)
	}
	return out, firstError
}
func parseTransaction(value any) (transaction, error) {
	m, ok := value.(map[string]any)
	if !ok || len(m) != 2 {
		return transaction{}, fail("invalid_transaction")
	}
	w, ok := m["write"].(map[string]any)
	if !ok {
		return transaction{}, fail("invalid_transaction")
	}
	sig, ok := m["signature"].(map[string]any)
	if !ok || len(sig) != 4 {
		return transaction{}, fail("invalid_transaction")
	}
	for _, key := range []string{"purpose", "key", "alg", "value"} {
		if _, ok := sig[key].(string); !ok {
			return transaction{}, fail("invalid_transaction")
		}
	}
	return transaction{w, sign.Signature{Purpose: sig["purpose"].(string), Key: sig["key"].(string), Alg: sig["alg"].(string), Value: sig["value"].(string)}}, nil
}

func (r *Repository) applyTransaction(state *kernel.State, policy *VerifiedPolicy, tx transaction, parent, tree string, valid map[string]sign.SignedRecord, bound map[string]bool) (*kernel.State, error) {
	domains, _ := r.config.Template["domain_schemas"].([]any)
	canonical, e := sign.NewCanonicalWrite(tx.Write, r.config.Schemas, domains)
	if e != nil {
		return nil, e
	}
	if tx.Signature.Purpose != sign.WritePurpose {
		return nil, sign.Fail(sign.PurposeMismatch, "write.signature.purpose")
	}
	if policy == nil {
		return nil, fail("no_verified_policy")
	}
	k, ok := policy.keys[tx.Signature.Key]
	if !ok {
		return nil, sign.Fail(sign.UnregisteredKey, "write.signature.key")
	}
	if k.identity != canonical.Actor() {
		return nil, sign.Fail(sign.WrongKey, "write.signature.key")
	}
	if e = (sign.Ed25519Verifier{}).Verify(sign.WritePurpose, canonical.Bytes(), tx.Signature, k.public); e != nil {
		return nil, e
	}
	origin := tx.Write["origin"].(map[string]any)
	if origin["space"] != policy.policy.SpaceID || origin["parent"] != parent || origin["tree"] != tree {
		return nil, fail("transaction_origin_mismatch")
	}
	if origin["policy"] != policy.Digest() {
		return nil, fail("transaction_policy_mismatch")
	}
	records := tx.Write["records"].([]any)
	paths := []string{}
	exact := []any{}
	for _, value := range records {
		b, _ := kernel.CanonicalJSON(value)
		signed, e := sign.ParseRecord(b, r.config.Schemas, domains)
		if e != nil {
			return nil, e
		}
		path := RecordPath(signed.Record)
		stored, ok := valid[path]
		wire, _ := encode(stored)
		if !ok || bound[path] || !bytes.Equal(b, wire) {
			return nil, fail("transaction_file_mismatch")
		}
		paths = append(paths, path)
		exact = append(exact, signed.Record.Value())
	}
	handle := tx.Write["receipt_handle"].(string)
	next, refusal := state.Fork(func() (string, error) { return handle, nil })
	if refusal != nil {
		return nil, refusal
	}
	before := len(next.Snapshot()["records"].([]any))
	receipt, refusal := next.Write(tx.Write["operation"].(map[string]any))
	if refusal != nil {
		return nil, fail(string(refusal.Code))
	}
	admitted := next.Snapshot()["records"].([]any)[before:]
	// Admission derives the evaluation cut from first-parent position. Concurrent
	// signed records may have the same local sequence stamp; that annotation never
	// orders the space. Compare every other admitted field exactly.
	for _, record := range exact {
		record.(map[string]any)["envelope"].(map[string]any)["recorded"].(map[string]any)["sequence"] = int64(0)
	}
	comparison := make([]any, 0, len(admitted))
	for _, record := range admitted {
		copied := detached(record.(map[string]any))
		copied["envelope"].(map[string]any)["recorded"].(map[string]any)["sequence"] = int64(0)
		comparison = append(comparison, copied)
	}
	a, _ := kernel.CanonicalJSON(comparison)
	b, _ := kernel.CanonicalJSON(exact)
	if !bytes.Equal(a, b) || receipt["receipt_handle"] != handle {
		return nil, fail("admission_output_mismatch")
	}
	restored, refusal := next.Fork(r.config.Mint)
	if refusal != nil {
		return nil, refusal
	}
	// Refusal must leave both state and output eligibility untouched. Publish
	// bindings only after admission, exact output comparison and restoration pass.
	for _, path := range paths {
		bound[path] = true
	}
	return restored, nil
}
