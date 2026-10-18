package space_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/relux-works/swarma-memory/kernel"
	"github.com/relux-works/swarma-memory/sign"
	"github.com/relux-works/swarma-memory/sign/localkey"
	"github.com/relux-works/swarma-memory/space"
)

// Every child git command uses this environment, including commands executed by
// the production adapter. No inherited git configuration, transport or key agent
// reaches a test; remotes below are newly created local bare repositories only.
func isolatedGitEnvironment(inherited []string) []string {
	out := []string{}
	for _, entry := range inherited {
		key := strings.SplitN(entry, "=", 2)[0]
		if strings.HasPrefix(key, "GIT_") || key == "SSH_AUTH_SOCK" {
			continue
		}
		out = append(out, entry)
	}
	return append(out, "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1", "GIT_AUTHOR_NAME=Space Test", "GIT_AUTHOR_EMAIL=space-test@example.invalid", "GIT_COMMITTER_NAME=Space Test", "GIT_COMMITTER_EMAIL=space-test@example.invalid", "GIT_TERMINAL_PROMPT=0")
}
func gitCommand(t *testing.T, dir string, env []string, args ...string) string {
	t.Helper()
	args = append([]string{"-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null"}, args...)
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = env
	b, e := cmd.CombinedOutput()
	if e != nil {
		t.Fatalf("git %s: %v\n%s", args, e, b)
	}
	return strings.TrimSpace(string(b))
}
func randomHandle() (string, error) {
	var b [16]byte
	_, e := rand.Read(b[:])
	return hex.EncodeToString(b[:]), e
}
func mapCopy(t *testing.T, m map[string]any) map[string]any {
	t.Helper()
	b, r := kernel.CanonicalJSON(m)
	if r != nil {
		t.Fatal(r)
	}
	v, r := kernel.DecodeJSON(b)
	if r != nil {
		t.Fatal(r)
	}
	return v.(map[string]any)
}
func jsonBytes(t *testing.T, v any) []byte {
	t.Helper()
	b, e := json.Marshal(v)
	check(t, e)
	return b
}
func putFile(t *testing.T, dir, path string, b []byte) {
	t.Helper()
	check(t, os.MkdirAll(filepath.Dir(filepath.Join(dir, path)), 0755))
	check(t, os.WriteFile(filepath.Join(dir, path), b, 0644))
}

type gitHarness struct {
	f                          fixture
	root, bare, seed, genesis  string
	env                        []string
	template, operation, query map[string]any
	second                     *localkey.Key
}

func newGitHarness(t *testing.T) *gitHarness {
	t.Helper()
	return newGitHarnessFormat(t, "sha1")
}

func newGitHarnessFormat(t *testing.T, format string) *gitHarness {
	t.Helper()
	f := newFixture(t)
	root := t.TempDir()
	env := isolatedGitEnvironment(os.Environ())
	b, e := os.ReadFile("../spec/kernel/vectors/semantic/S14.json")
	check(t, e)
	v, r := kernel.DecodeJSON(b)
	if r != nil {
		t.Fatal(r)
	}
	doc := v.(map[string]any)
	template := doc["initial_state"].(map[string]any)
	policy := template["policy"].(map[string]any)
	second := key(t, "subj:h2")
	secondProjection := mapCopy(t, template["projection_rules"].([]any)[0].(map[string]any))
	secondProjection["id"] = "projection:second"
	secondProjection["issuer"] = second.Identity()
	secondProjection["perspective"].(map[string]any)["principal"] = second.Identity()
	template["projection_rules"] = append(template["projection_rules"].([]any), secondProjection)
	grants := policy["grants"].([]any)
	for _, g := range append([]any{}, grants...) {
		copy := mapCopy(t, g.(map[string]any))
		copy["principal"] = second.Identity()
		grants = append(grants, copy)
	}
	policy["grants"] = grants
	facts := []any{}
	reviews := []any{}
	for _, id := range []string{"rec:a", "rec:b", "rec:c", "rec:d", "rec:e", "rec:f", "rec:g", "rec:r1", "rec:r2", "rec:r3", "rec:bad", "rec:good", "rec:second", "rec:secret"} {
		for version := int64(1); version <= 3; version++ {
			fact := mapCopy(t, policy["lineage_facts"].([]any)[0].(map[string]any))
			fact["output"] = map[string]any{"id": id, "version": version}
			facts = append(facts, fact)
			reviews = append(reviews, map[string]any{"record": map[string]any{"id": id, "version": version}, "reviewer": "subj:h1", "result": "allow"})
		}
	}
	policy["lineage_facts"] = facts
	policy["reviews"] = reviews
	p := f.policy.Policy
	p.Writers[0].Kinds = []string{"assertion", "revision"}
	p.Writers[0].Schemas = append(p.Writers[0].Schemas, nil)
	other := p.Writers[0]
	other.Identity = second.Identity()
	p.Writers = append(p.Writers, other)
	p.Keys = append(p.Keys, registration(t, f.owner, second, p.SpaceID, 1))
	f.policy = signPolicy(t, f.owner, p)
	canonical, e := space.NewCanonicalPolicy(p)
	check(t, e)
	f.anchor = sign.PolicyDigest(canonical.Bytes())
	f.template = template
	bare := filepath.Join(root, "remote.git")
	seed := filepath.Join(root, "seed")
	gitCommand(t, root, env, "init", "--bare", "--template=", "--object-format="+format, "--initial-branch=main", bare)
	gitCommand(t, root, env, "init", "--template=", "--object-format="+format, "--initial-branch=main", seed)
	putFile(t, seed, "space.json", jsonBytes(t, f.policy))
	gitCommand(t, seed, env, "add", "space.json")
	gitCommand(t, seed, env, "commit", "-m", "Initialize synthetic space")
	genesis := gitCommand(t, seed, env, "rev-parse", "HEAD")
	gitCommand(t, seed, env, "remote", "add", "origin", bare)
	gitCommand(t, seed, env, "push", "origin", "main")
	return &gitHarness{f, root, bare, seed, genesis, env, template, doc["operations"].([]any)[0].(map[string]any), doc["query"].(map[string]any), second}
}
func (h *gitHarness) clone(t *testing.T, name string) (*space.Repository, string, string) {
	t.Helper()
	dir := filepath.Join(h.root, name)
	cache := filepath.Join(h.root, name+"-cache")
	g := space.Git{Directory: dir, Environment: h.env, UnsignedCommits: true}
	check(t, space.Clone(context.Background(), g, h.bare, "main"))
	r, e := space.Open(space.Config{Git: g, Branch: "main", CacheDirectory: cache, GenesisDigest: h.f.anchor, Template: h.template, Schemas: h.f.schemas, Mint: randomHandle})
	check(t, e)
	return r, dir, cache
}
func (h *gitHarness) open(t *testing.T, dir, cache string) *space.Repository {
	t.Helper()
	r, e := space.Open(space.Config{Git: space.Git{Directory: dir, Environment: h.env, UnsignedCommits: true}, Branch: "main", CacheDirectory: cache, GenesisDigest: h.f.anchor, Template: h.template, Schemas: h.f.schemas, Mint: randomHandle})
	check(t, e)
	return r
}
func (h *gitHarness) op(t *testing.T, id string, actor string) map[string]any {
	t.Helper()
	op := mapCopy(t, h.operation)
	op["idempotency_key"] = "key:" + id
	op["context"].(map[string]any)["actor"] = actor
	record := op["proposals"].([]any)[0].(map[string]any)
	e := record["envelope"].(map[string]any)
	e["id"] = id
	e["issuer"] = actor
	e["perspective"].(map[string]any)["principal"] = actor
	return op
}
func writeRequest(op map[string]any, signer sign.WriteSigner, retries int) space.WriteRequest {
	return space.WriteRequest{Build: func(map[string]any) (map[string]any, error) { return op, nil }, Signer: signer, MaxRetries: retries}
}
func mustWrite(t *testing.T, r *space.Repository, op map[string]any, signer sign.WriteSigner) space.WriteResult {
	t.Helper()
	result, e := r.Write(context.Background(), writeRequest(op, signer, 2))
	check(t, e)
	return result
}
func errorIs(t *testing.T, e error, code string) {
	t.Helper()
	var d *space.Error
	var s *sign.Diagnostic
	if errors.As(e, &d) && d.Code == code || errors.As(e, &s) && string(s.Code) == code {
		return
	}
	t.Fatalf("error %v, want %s", e, code)
}
func expectDiagnostic(t *testing.T, r *space.Repository, code string) {
	t.Helper()
	for _, d := range r.Diagnostics() {
		if d.Code == code {
			return
		}
	}
	t.Fatalf("missing %s: %+v", code, r.Diagnostics())
}
func (h *gitHarness) readQuery(t *testing.T, r *space.Repository, actor string) map[string]any {
	q := mapCopy(t, h.query)
	q["principal"] = actor
	q["cut"].(map[string]any)["memory"] = r.Snapshot()["runtime"].(map[string]any)["memory_cut"]
	return q
}

// TestGitIsolation rejects every inherited config/transport/object override while
// preserving ordinary caller variables. A real child reports unsigned commits.
func TestGitIsolation(t *testing.T) {
	inherited := []string{"PATH=" + os.Getenv("PATH"), "GIT_CONFIG_COUNT=99", "GIT_CONFIG_KEY_0=include.path", "GIT_CONFIG_VALUE_0=forbidden", "GIT_SSH_COMMAND=forbidden", "SSH_AUTH_SOCK=forbidden", "GIT_DIR=forbidden", "GIT_WORK_TREE=forbidden", "GIT_INDEX_FILE=forbidden", "GIT_COMMON_DIR=forbidden", "GIT_CONFIG_PARAMETERS=forbidden", "GIT_AUTHOR_NAME=forbidden", "ORDINARY=preserved"}
	env := isolatedGitEnvironment(inherited)
	for _, entry := range env {
		if strings.Contains(entry, "forbidden") || strings.HasPrefix(entry, "GIT_CONFIG_COUNT=") || strings.HasPrefix(entry, "GIT_CONFIG_KEY_") || strings.HasPrefix(entry, "GIT_CONFIG_VALUE_") {
			t.Fatalf("inherited override leaked: %s", entry)
		}
	}
	h := newGitHarness(t)
	if got := gitCommand(t, h.seed, h.env, "log", "-1", "--format=%G?"); got != "N" {
		t.Fatalf("test commit signed: %s", got)
	}
	if got := gitCommand(t, h.seed, h.env, "config", "--get", "commit.gpgsign"); got != "false" {
		t.Fatal(got)
	}
}

// canonicalView normalizes only the declared fresh handle after verifying its
// equality binding throughout the full view. Every other value stays exact.
func canonicalView(t *testing.T, view map[string]any) []byte {
	t.Helper()
	copy := mapCopy(t, view)
	handle := copy["authorized_snapshot_handle"]
	var walk func(any)
	walk = func(value any) {
		switch v := value.(type) {
		case map[string]any:
			for k, x := range v {
				if k == "authorized_snapshot_handle" {
					if x != handle {
						t.Fatal("view handle binding changed")
					}
					v[k] = "@snapshot"
				} else {
					walk(x)
				}
			}
		case []any:
			for _, x := range v {
				walk(x)
			}
		}
	}
	walk(copy)
	b, r := kernel.CanonicalJSON(copy)
	if r != nil {
		t.Fatal(r)
	}
	return b
}

// TestGitRoundTripRebuild proves cross-identity reads, exact idempotency and
// changed-content refusal. Deleting the cache rebuilds byte-identical storage and
// the complete canonical view after only its fresh handle is equality-normalized.
func TestGitRoundTripRebuild(t *testing.T) {
	h := newGitHarness(t)
	a, _, _ := h.clone(t, "a")
	b, dir, cache := h.clone(t, "b")
	op := h.op(t, "rec:a", h.f.writer.Identity())
	first := mustWrite(t, a, op, h.f.writer)
	replay := mapCopy(t, op)
	replay["context"].(map[string]any)["at"] = "2026-10-18T00:00:00Z"
	again := mustWrite(t, a, replay, h.f.writer)
	if !reflect.DeepEqual(first.Receipt, again.Receipt) || again.PushAttempts != 0 || first.Commit != again.Commit {
		t.Fatal("idempotency changed receipt/head")
	}
	changed := mapCopy(t, op)
	changed["proposals"].([]any)[0].(map[string]any)["body"].(map[string]any)["content"].([]any)[0].(map[string]any)["value"] = "beta"
	_, e := a.Write(context.Background(), writeRequest(changed, h.f.writer, 2))
	errorIs(t, e, "idempotency_conflict")
	mustWrite(t, b, h.op(t, "rec:b", h.second.Identity()), h.second)
	check(t, a.Sync(context.Background()))
	for _, repo := range []*space.Repository{a, b} {
		for _, principal := range []string{h.f.writer.Identity(), h.second.Identity()} {
			for _, projection := range []string{"projection:main", "projection:second"} {
				q := h.readQuery(t, repo, principal)
				q["projection_rule"].(map[string]any)["id"] = projection
				view, e := repo.Read(q)
				check(t, e)
				if len(view["items"].([]any)) != 1 {
					t.Fatalf("cross-identity projection missing: %+v", view)
				}
			}
		}
	}
	baselineQuery := h.readQuery(t, b, h.f.writer.Identity())
	baselineView, e := b.Read(baselineQuery)
	check(t, e)
	baselineCanonicalView := canonicalView(t, baselineView)
	before, _ := kernel.CanonicalJSON(b.Snapshot())
	diagnostics := b.Diagnostics()
	cursor := b.Cursor()
	cached := map[string]any{"cursor": cursor, "snapshot": map[string]any{"records": []any{"forged-cache-record"}}}
	check(t, os.WriteFile(filepath.Join(cache, "index.json"), jsonBytes(t, cached), 0600))
	reopened := h.open(t, dir, cache)
	unpoisoned, _ := kernel.CanonicalJSON(reopened.Snapshot())
	if !bytes.Equal(before, unpoisoned) {
		t.Fatal("cache bytes injected state")
	}
	check(t, os.Remove(filepath.Join(cache, "index.json")))
	rebuilt := h.open(t, dir, cache)
	check(t, rebuilt.Sync(context.Background()))
	after, _ := kernel.CanonicalJSON(rebuilt.Snapshot())
	if !bytes.Equal(before, after) || cursor != rebuilt.Cursor() || !reflect.DeepEqual(diagnostics, rebuilt.Diagnostics()) {
		t.Fatal("rebuild drift")
	}
	rebuiltView, e := rebuilt.Read(baselineQuery)
	check(t, e)
	if !bytes.Equal(baselineCanonicalView, canonicalView(t, rebuiltView)) {
		t.Fatal("canonical evaluation view changed on rebuild")
	}
	if len(rebuilt.Diagnostics()) != 0 {
		t.Fatalf("unexpected diagnostics %+v", rebuilt.Diagnostics())
	}
}

type barrierSigner struct {
	*localkey.Key
	arrivals *sync.WaitGroup
	once     sync.Once
}

func (s *barrierSigner) Sign(record sign.CanonicalRecord) (sign.Signature, error) {
	s.once.Do(func() { s.arrivals.Done(); s.arrivals.Wait() })
	return s.Key.Sign(record)
}

// TestGitConcurrentWriters forces two writers to sign from the same verified
// head. A common single-valued sequence has exactly one winner and both readers
// agree; distinct sequences retry/re-sign successfully after the real NFF race.
func TestGitConcurrentWriters(t *testing.T) {
	for _, conflict := range []bool{true, false} {
		t.Run(fmt.Sprint(conflict), func(t *testing.T) {
			h := newGitHarness(t)
			if conflict {
				h.template["domain_schemas"].([]any)[0].(map[string]any)["cardinality"].(map[string]any)["mode"] = "single"
			}
			a, _, _ := h.clone(t, "a")
			b, _, _ := h.clone(t, "b")
			barrier := &sync.WaitGroup{}
			barrier.Add(2)
			type outcome struct {
				result space.WriteResult
				err    error
			}
			out := make(chan outcome, 2)
			for i, repo := range []*space.Repository{a, b} {
				go func(i int, repo *space.Repository) {
					id := []string{"rec:a", "rec:b"}[i]
					result, e := repo.Write(context.Background(), writeRequest(h.op(t, id, h.f.writer.Identity()), &barrierSigner{Key: h.f.writer, arrivals: barrier}, 2))
					out <- outcome{result, e}
				}(i, repo)
			}
			x, y := <-out, <-out
			if conflict {
				successes := 0
				for _, o := range []outcome{x, y} {
					if o.err == nil {
						successes++
					} else {
						errorIs(t, o.err, "version_conflict")
					}
				}
				if successes != 1 {
					t.Fatalf("winners %d: %v %v", successes, x.err, y.err)
				}
			} else {
				check(t, x.err)
				check(t, y.err)
				if x.result.PushAttempts+y.result.PushAttempts != 3 {
					t.Fatalf("retry counts %d %d", x.result.PushAttempts, y.result.PushAttempts)
				}
			}
			check(t, a.Sync(context.Background()))
			check(t, b.Sync(context.Background()))
			ab, _ := kernel.CanonicalJSON(a.Snapshot())
			bb, _ := kernel.CanonicalJSON(b.Snapshot())
			if !bytes.Equal(ab, bb) {
				t.Fatal("fetch-order disagreement")
			}
			expected := 2
			if conflict {
				expected = 1
			}
			if len(a.Snapshot()["records"].([]any)) != expected {
				t.Fatal("wrong admitted count")
			}
			if len(a.Diagnostics()) != 0 || len(b.Diagnostics()) != 0 {
				t.Fatal("successful retry left rejected transaction diagnostics")
			}
		})
	}
}

type interferingSigner struct {
	*localkey.Key
	interfere func()
	count     atomic.Int32
}

func (s *interferingSigner) SignWrite(w sign.CanonicalWrite) (sign.Signature, error) {
	s.count.Add(1)
	s.interfere()
	return s.Key.SignWrite(w)
}

// TestGitRetryBound advances the real remote before every push; two additional
// retries allow exactly three attempts and never publish the losing record.
func TestGitRetryBound(t *testing.T) {
	h := newGitHarness(t)
	a, _, _ := h.clone(t, "a")
	other, _, _ := h.clone(t, "other")
	n := 0
	signer := &interferingSigner{Key: h.f.writer, interfere: func() {
		id := []string{"rec:b", "rec:c", "rec:d"}[n]
		n++
		mustWrite(t, other, h.op(t, id, h.f.writer.Identity()), h.f.writer)
	}}
	result, e := a.Write(context.Background(), writeRequest(h.op(t, "rec:a", h.f.writer.Identity()), signer, 2))
	errorIs(t, e, "retry_exhausted")
	if result.PushAttempts != 3 || signer.count.Load() != 3 || len(a.Snapshot()["records"].([]any)) != 3 {
		t.Fatalf("bound not respected: %+v %d", result, signer.count.Load())
	}
}

const writeMessagePrefix = "swarma-memory transactions/1\n\n"

// transactionFiles uses the production kernel and signer to prepare a legitimate
// transaction for a direct-git adversarial push. It is not an admission oracle.
func (h *gitHarness) transactionFiles(t *testing.T, snapshot map[string]any, op map[string]any, signer *localkey.Key) (map[string][]byte, map[string]any) {
	t.Helper()
	state, f := kernel.NewState(snapshot, h.f.schemas, randomHandle)
	if f != nil {
		t.Fatal(f)
	}
	before := len(snapshot["records"].([]any))
	receipt, f := state.Write(op)
	if f != nil {
		t.Fatal(f)
	}
	files := map[string][]byte{}
	records := []any{}
	for _, v := range state.Snapshot()["records"].([]any)[before:] {
		record, e := sign.NewCanonicalRecord(v, h.f.schemas, h.template["domain_schemas"].([]any))
		check(t, e)
		signature, e := signer.Sign(record)
		check(t, e)
		signed := sign.SignedRecord{Record: record, Signature: signature}
		b := jsonBytes(t, signed)
		files[space.RecordPath(record)] = b
		tree, r := kernel.DecodeJSON(b)
		if r != nil {
			t.Fatal(r)
		}
		records = append(records, tree)
	}
	write := map[string]any{"operation": op, "records": records, "receipt_handle": receipt["receipt_handle"], "origin": h.initialOrigin(t)}
	canonical, e := sign.NewCanonicalWrite(write, h.f.schemas, h.template["domain_schemas"].([]any))
	check(t, e)
	signature, e := signer.SignWrite(canonical)
	check(t, e)
	return files, map[string]any{"write": write, "signature": signature}
}

func (h *gitHarness) initialOrigin(t *testing.T) map[string]any {
	return map[string]any{"space": h.f.policy.Policy.SpaceID, "parent": h.genesis, "tree": gitCommand(t, h.seed, h.env, "rev-parse", h.genesis+"^{tree}"), "policy": h.f.anchor}
}

// Bind fixtures using Git's independently computed staged tree before applying
// signature or metadata faults. Existing signed transplants must not be rebound.
func bindTransactions(t *testing.T, h *gitHarness, dir string, files map[string][]byte, policy space.SignedPolicy, txs ...map[string]any) {
	t.Helper()
	for path, data := range files {
		putFile(t, dir, path, data)
		gitCommand(t, dir, h.env, "add", "--", path)
	}
	parent := gitCommand(t, dir, h.env, "rev-parse", "HEAD")
	tree := gitCommand(t, dir, h.env, "write-tree")
	canonicalPolicy, e := space.NewCanonicalPolicy(policy.Policy)
	check(t, e)
	for _, tx := range txs {
		write := tx["write"].(map[string]any)
		write["origin"] = map[string]any{"space": policy.Policy.SpaceID, "parent": parent, "tree": tree, "policy": sign.PolicyDigest(canonicalPolicy.Bytes())}
		canonical, e := sign.NewCanonicalWrite(write, h.f.schemas, h.template["domain_schemas"].([]any))
		check(t, e)
		key := h.f.writer
		if canonical.Actor() == h.second.Identity() {
			key = h.second
		}
		sig, e := key.SignWrite(canonical)
		check(t, e)
		tx["signature"] = sig
	}
}
func rawCommit(t *testing.T, h *gitHarness, dir string, files map[string][]byte, txs []map[string]any) string {
	t.Helper()
	paths := []string{}
	for path, b := range files {
		putFile(t, dir, path, b)
		paths = append(paths, path)
	}
	gitCommand(t, dir, h.env, append([]string{"add", "--"}, paths...)...)
	message := "Direct git change"
	if txs != nil {
		message = writeMessagePrefix + string(jsonBytes(t, txs))
	}
	gitCommand(t, dir, h.env, "commit", "-m", message)
	return gitCommand(t, dir, h.env, "rev-parse", "HEAD")
}
func (h *gitHarness) seedAtRemote(t *testing.T) {
	t.Helper()
	gitCommand(t, h.seed, h.env, "fetch", "origin", "main")
	gitCommand(t, h.seed, h.env, "switch", "--detach", "origin/main")
}
func (h *gitHarness) push(t *testing.T, dir string) {
	t.Helper()
	gitCommand(t, dir, h.env, "push", "origin", "HEAD:refs/heads/main")
}
func nextPolicy(t *testing.T, h *gitHarness, previous space.SignedPolicy, change func(*space.Policy)) space.SignedPolicy {
	t.Helper()
	p := clone(t, previous.Policy)
	canonical, e := space.NewCanonicalPolicy(p)
	check(t, e)
	digest := sign.PolicyDigest(canonical.Bytes())
	p.Previous = &digest
	p.Version++
	p.Keys = nil
	for _, k := range []*localkey.Key{h.f.owner, h.f.writer, h.second} {
		p.Keys = append(p.Keys, registration(t, h.f.owner, k, p.SpaceID, p.Version))
	}
	change(&p)
	return signPolicy(t, h.f.owner, p)
}

// TestGitForgedRecords excludes each direct-git forgery while admitting a valid
// independently signed neighbour in the very same commit/push. Previously
// admitted bytes survive a rewrite attempt; invalid policy never grants rights.
func TestGitForgedRecords(t *testing.T) {
	for _, kind := range []string{"bad_signature", "unregistered_key", "outside_grant", "rewrite", "non_owner_policy"} {
		t.Run(kind, func(t *testing.T) {
			h := newGitHarness(t)
			repo, _, _ := h.clone(t, "reader")
			mustWrite(t, repo, h.op(t, "rec:a", h.f.writer.Identity()), h.f.writer)
			before := repo.Snapshot()["records"].([]any)[0]
			files, tx := h.transactionFiles(t, repo.Snapshot(), h.op(t, "rec:good", h.f.writer.Identity()), h.f.writer)
			value := h.f.record.Value()
			value["envelope"].(map[string]any)["id"] = "rec:bad"
			expected := ""
			switch kind {
			case "non_owner_policy":
				p := nextPolicy(t, h, h.f.policy, func(*space.Policy) {}).Policy
				p.Author = h.f.writer.Identity()
				files["space.json"] = jsonBytes(t, signPolicy(t, h.f.writer, p))
				expected = "unauthorized_owner"
			default:
				signer := h.f.writer
				if kind == "unregistered_key" {
					signer = key(t, h.f.writer.Identity())
					expected = "unregistered_key"
				}
				if kind == "outside_grant" {
					value["envelope"].(map[string]any)["admission_class"] = "semantic_inference"
					expected = "grant_mismatch"
				}
				if kind == "rewrite" {
					value["envelope"].(map[string]any)["id"] = "rec:a"
					value["body"].(map[string]any)["content"].([]any)[0].(map[string]any)["value"] = "forged replacement"
					expected = "record_rewritten"
				}
				record, e := sign.NewCanonicalRecord(value, h.f.schemas, h.template["domain_schemas"].([]any))
				check(t, e)
				signature, e := signer.Sign(record)
				check(t, e)
				if kind == "bad_signature" {
					signature.Value = strings.Repeat("A", 86) + "=="
					expected = "invalid_signature"
				}
				files[space.RecordPath(record)] = jsonBytes(t, sign.SignedRecord{Record: record, Signature: signature})
			}
			h.seedAtRemote(t)
			bindTransactions(t, h, h.seed, files, h.f.policy, tx)
			rawCommit(t, h, h.seed, files, []map[string]any{tx})
			h.push(t, h.seed)
			check(t, repo.Sync(context.Background()))
			expectDiagnostic(t, repo, expected)
			records := repo.Snapshot()["records"].([]any)
			if len(records) != 2 || !reflect.DeepEqual(before, records[0]) {
				t.Fatalf("forgery changed state: %+v", records)
			}
			view, e := repo.Read(h.readQuery(t, repo, h.f.writer.Identity()))
			check(t, e)
			if len(view["items"].([]any)) != 2 {
				t.Fatal("valid neighbour excluded")
			}
		})
	}
}

// TestGitCompetingMergedVersions introduces two individually valid signed writes
// from the same base via an actual merge. First-parent A wins regardless of the
// reader's earlier fetch of B; B is retained only as version_conflict diagnostics.
func TestGitCompetingMergedVersions(t *testing.T) {
	h := newGitHarness(t)
	h.template["domain_schemas"].([]any)[0].(map[string]any)["cardinality"].(map[string]any)["mode"] = "single"
	a, aDir, _ := h.clone(t, "a")
	b, bDir, _ := h.clone(t, "b")
	check(t, b.Sync(context.Background()))
	files, tx := h.transactionFiles(t, b.Snapshot(), h.op(t, "rec:b", h.f.writer.Identity()), h.f.writer)
	bindTransactions(t, h, bDir, files, h.f.policy, tx)
	bHead := rawCommit(t, h, bDir, files, []map[string]any{tx})
	first := mustWrite(t, a, h.op(t, "rec:a", h.f.writer.Identity()), h.f.writer)
	gitCommand(t, aDir, h.env, "fetch", bDir, bHead)
	gitCommand(t, aDir, h.env, "merge", "--no-ff", "-m", "Merge concurrent synthetic write", "FETCH_HEAD")
	h.push(t, aDir)
	check(t, a.Sync(context.Background()))
	check(t, b.Sync(context.Background()))
	expectDiagnostic(t, a, "version_conflict")
	expectDiagnostic(t, b, "version_conflict")
	x, _ := kernel.CanonicalJSON(a.Snapshot())
	y, _ := kernel.CanonicalJSON(b.Snapshot())
	if !bytes.Equal(x, y) || len(a.Snapshot()["records"].([]any)) != 1 {
		t.Fatal("merge winner depends on fetch order")
	}
	if a.Snapshot()["records"].([]any)[0].(map[string]any)["envelope"].(map[string]any)["id"] != "rec:a" || first.Commit == a.Cursor() {
		t.Fatal("wrong first-parent winner")
	}
}

// TestGitPolicyForks proves both genesis-valid owner-signed forks resolve by the
// first policy in first-parent history, in both orders. A losing fork cannot
// grant a writer, and its later continuation cannot replace the winning chain.
// Earlier records remain bound to their original policy, not the latest keys.
func TestGitPolicyForks(t *testing.T) {
	for _, denyFirst := range []bool{true, false} {
		t.Run(fmt.Sprint(denyFirst), func(t *testing.T) {
			h := newGitHarness(t)
			a, _, _ := h.clone(t, "a")
			b, _, _ := h.clone(t, "b")
			mustWrite(t, a, h.op(t, "rec:a", h.second.Identity()), h.second)
			check(t, b.Sync(context.Background()))
			allow := nextPolicy(t, h, h.f.policy, func(p *space.Policy) { p.Limits.MaxFieldBytes = 7000 })
			deny := nextPolicy(t, h, h.f.policy, func(p *space.Policy) { p.Writers = p.Writers[:1] })
			first, loser := allow, deny
			if denyFirst {
				first, loser = deny, allow
			}
			for _, p := range []space.SignedPolicy{first, loser} {
				_, e := space.VerifyChain([]space.SignedPolicy{h.f.policy, p}, h.f.anchor)
				check(t, e)
			}
			h.seedAtRemote(t)
			rawCommit(t, h, h.seed, map[string][]byte{"space.json": jsonBytes(t, first)}, nil)
			h.push(t, h.seed)
			check(t, a.Sync(context.Background()))
			rawCommit(t, h, h.seed, map[string][]byte{"space.json": jsonBytes(t, loser)}, nil)
			h.push(t, h.seed)
			check(t, a.Sync(context.Background()))
			expectDiagnostic(t, a, "policy_sequence")
			// This manually prepared write is valid under the allow fork only.
			files, tx := h.transactionFiles(t, a.Snapshot(), h.op(t, "rec:second", h.second.Identity()), h.second)
			bindTransactions(t, h, h.seed, files, first, tx)
			rawCommit(t, h, h.seed, files, []map[string]any{tx})
			h.push(t, h.seed)
			check(t, a.Sync(context.Background()))
			expected := 2
			if denyFirst {
				expected = 1
				expectDiagnostic(t, a, "grant_mismatch")
			}
			if len(a.Snapshot()["records"].([]any)) != expected {
				t.Fatal("arbitrary policy fork selected")
			}
			continuation := nextPolicy(t, h, loser, func(*space.Policy) {})
			rawCommit(t, h, h.seed, map[string][]byte{"space.json": jsonBytes(t, continuation)}, nil)
			h.push(t, h.seed)
			check(t, a.Sync(context.Background()))
			check(t, b.Sync(context.Background()))
			x, _ := kernel.CanonicalJSON(a.Snapshot())
			y, _ := kernel.CanonicalJSON(b.Snapshot())
			if !bytes.Equal(x, y) {
				t.Fatal("policy fork depends on fetch order")
			}
			// A valid continuation of the winning branch still advances after rejected files.
			winning := nextPolicy(t, h, first, func(*space.Policy) {})
			rawCommit(t, h, h.seed, map[string][]byte{"space.json": jsonBytes(t, winning)}, nil)
			h.push(t, h.seed)
			check(t, a.Sync(context.Background()))
			if len(a.Snapshot()["records"].([]any)) != expected {
				t.Fatal("policy update revalidated historical records under latest grants")
			}
		})
	}
}

// TestGitRewrittenHistory performs the exact remote reference transition of a
// force push via update-ref inside the temporary bare fixture (no force-push
// command is used). Dropping a verified commit, including replaying identical
// files under new commits, cannot advance the cursor or alter served evidence.
func TestGitRewrittenHistory(t *testing.T) {
	for _, readd := range []bool{false, true} {
		t.Run(fmt.Sprint(readd), func(t *testing.T) {
			h := newGitHarness(t)
			repo, dir, cache := h.clone(t, "reader")
			mustWrite(t, repo, h.op(t, "rec:a", h.f.writer.Identity()), h.f.writer)
			cursor := repo.Cursor()
			snapshot, _ := kernel.CanonicalJSON(repo.Snapshot())
			indexBefore, e := os.ReadFile(filepath.Join(cache, "index.json"))
			check(t, e)
			replacement := h.genesis
			if readd {
				// Start from genesis with the exact former tree/message; only parentage differs.
				tree := gitCommand(t, dir, h.env, "rev-parse", cursor+"^{tree}")
				message := gitCommand(t, dir, h.env, "show", "-s", "--format=%B", cursor)
				cmd := exec.Command("git", "-c", "commit.gpgsign=false", "commit-tree", tree, "-p", h.genesis, "-m", "Re-added identical files\n\n"+message)
				cmd.Dir = dir
				cmd.Env = h.env
				out, e := cmd.Output()
				check(t, e)
				replacement = strings.TrimSpace(string(out))
				if replacement == cursor {
					t.Fatal("rewrite fixture did not change commit")
				}
				gitCommand(t, dir, h.env, "push", "origin", replacement+":refs/heads/replacement")
			}
			gitCommand(t, h.root, h.env, "--git-dir", h.bare, "update-ref", "refs/heads/main", replacement, cursor)
			errorIs(t, repo.Sync(context.Background()), "history_rewritten")
			after, _ := kernel.CanonicalJSON(repo.Snapshot())
			indexAfter, e := os.ReadFile(filepath.Join(cache, "index.json"))
			check(t, e)
			if cursor != repo.Cursor() || !bytes.Equal(snapshot, after) || !bytes.Equal(indexBefore, indexAfter) {
				t.Fatal("rewrite changed verified cache")
			}
			view, e := repo.Read(h.readQuery(t, repo, h.f.writer.Identity()))
			check(t, e)
			if len(view["items"].([]any)) != 1 {
				t.Fatal("last verified read unavailable")
			}
			reopened := h.open(t, dir, cache)
			errorIs(t, reopened.Sync(context.Background()), "history_rewritten")
			restored, _ := kernel.CanonicalJSON(reopened.Snapshot())
			if !bytes.Equal(snapshot, restored) {
				t.Fatal("restart lost pinned verified state")
			}
		})
	}
}

func (h *gitHarness) revision(t *testing.T, target, revision, issuer, actor string, replace bool) map[string]any {
	t.Helper()
	op := h.op(t, target, issuer)
	proposal := op["proposals"].([]any)[0].(map[string]any)
	envelope := mapCopy(t, proposal["envelope"].(map[string]any))
	envelope["id"] = revision
	envelope["kind"] = "revision"
	envelope["schema"] = nil
	reference := map[string]any{"id": target, "version": int64(1)}
	body := map[string]any{"relation": "withdraw", "target": reference, "replacement": nil, "availability": nil, "authority_receipt": nil}
	delete(op, "proposals")
	op["op"] = "revise"
	op["idempotency_key"] = "key:" + revision
	op["revision"] = map[string]any{"envelope": envelope, "body": body}
	op["replacement"] = nil
	op["expected_version"] = mapCopy(t, reference)
	op["context"].(map[string]any)["actor"] = actor
	if replace {
		body["relation"] = "replace"
		body["replacement"] = map[string]any{"id": target, "version": int64(2)}
		proposal["envelope"].(map[string]any)["version"] = int64(2)
		proposal["body"].(map[string]any)["content"].([]any)[0].(map[string]any)["value"] = "revised"
		op["replacement"] = proposal
	}
	return op
}

// TestGitRevisionAuthority exercises issuer-local revision through the full write
// path in both identity directions. A non-issuer cannot withdraw another record;
// its state and remote stay unchanged. Each issuer can replace its own sequence,
// and a concurrent stale expected-version retry returns version_conflict.
func TestGitRevisionAuthority(t *testing.T) {
	h := newGitHarness(t)
	a, _, _ := h.clone(t, "a")
	b, _, _ := h.clone(t, "b")
	mustWrite(t, a, h.op(t, "rec:a", h.f.writer.Identity()), h.f.writer)
	mustWrite(t, b, h.op(t, "rec:b", h.second.Identity()), h.second)
	check(t, a.Sync(context.Background()))
	for i, pair := range []struct {
		target, issuer string
		repo           *space.Repository
		signer         *localkey.Key
	}{{"rec:a", h.f.writer.Identity(), b, h.second}, {"rec:b", h.second.Identity(), a, h.f.writer}} {
		check(t, pair.repo.Sync(context.Background()))
		before, _ := kernel.CanonicalJSON(pair.repo.Snapshot())
		cursor := pair.repo.Cursor()
		op := h.revision(t, pair.target, []string{"rec:r1", "rec:r2"}[i], pair.issuer, pair.signer.Identity(), false)
		_, e := pair.repo.Write(context.Background(), writeRequest(op, pair.signer, 2))
		errorIs(t, e, "representation_invalid")
		after, _ := kernel.CanonicalJSON(pair.repo.Snapshot())
		if !bytes.Equal(before, after) || pair.repo.Cursor() != cursor {
			t.Fatal("nonissuer changed state")
		}
	}
	mustWrite(t, a, h.revision(t, "rec:a", "rec:r1", h.f.writer.Identity(), h.f.writer.Identity(), true), h.f.writer)
	mustWrite(t, b, h.revision(t, "rec:b", "rec:r2", h.second.Identity(), h.second.Identity(), true), h.second)
	check(t, a.Sync(context.Background()))
	for _, repo := range []*space.Repository{a, b} {
		for _, projection := range []string{"projection:main", "projection:second"} {
			q := h.readQuery(t, repo, h.f.writer.Identity())
			q["projection_rule"].(map[string]any)["id"] = projection
			view, e := repo.Read(q)
			check(t, e)
			items := view["items"].([]any)
			if len(items) != 1 || items[0].(map[string]any)["ref"].(map[string]any)["version"] != int64(2) {
				t.Fatal("revision not reflected in read")
			}
		}
	}
}

// TestGitExpectedVersionAfterFetch forces a competing replacement between sign
// and push. Both requests began from v1; the loser's fetched CAS refuses v1 even
// with retry budget left, and it never signs or publishes another attempt.
func TestGitExpectedVersionAfterFetch(t *testing.T) {
	h := newGitHarness(t)
	a, _, _ := h.clone(t, "a")
	b, _, _ := h.clone(t, "b")
	mustWrite(t, a, h.op(t, "rec:a", h.f.writer.Identity()), h.f.writer)
	signer := &interferingSigner{Key: h.f.writer, interfere: func() {
		mustWrite(t, b, h.revision(t, "rec:a", "rec:r2", h.f.writer.Identity(), h.f.writer.Identity(), true), h.f.writer)
	}}
	result, e := a.Write(context.Background(), writeRequest(h.revision(t, "rec:a", "rec:r1", h.f.writer.Identity(), h.f.writer.Identity(), true), signer, 3))
	errorIs(t, e, "version_conflict")
	if result.PushAttempts != 1 || signer.count.Load() != 1 {
		t.Fatal("stale CAS was retried")
	}
	if len(a.Snapshot()["records"].([]any)) != 3 {
		t.Fatal("losing replacement partly admitted")
	}
}

// TestGitReadSpaces reads one identity's projection from two independently
// signed readable spaces in a single library call, preserving per-space cuts and
// data classification. A signed reader removal refuses subsequent access.
func TestGitReadSpaces(t *testing.T) {
	h := newGitHarness(t)
	other := newGitHarness(t)
	p := other.f.policy.Policy
	p.SpaceID = "space:second"
	p.Keys = nil
	for _, k := range []*localkey.Key{other.f.owner, other.f.writer, other.second} {
		p.Keys = append(p.Keys, registration(t, other.f.owner, k, p.SpaceID, 1))
	}
	other.f.policy = signPolicy(t, other.f.owner, p)
	canonical, e := space.NewCanonicalPolicy(p)
	check(t, e)
	other.f.anchor = sign.PolicyDigest(canonical.Bytes())
	for _, raw := range other.template["policy"].(map[string]any)["grants"].([]any) {
		raw.(map[string]any)["space"] = p.SpaceID
	}
	other.operation["proposals"].([]any)[0].(map[string]any)["envelope"].(map[string]any)["space"] = p.SpaceID
	other.query["scope"].(map[string]any)["space"] = p.SpaceID
	// This fixture has no readers/cursors yet; replace its pinned genesis by a new
	// owner-signed initialization commit using a normal append, not a forced ref.
	putFile(t, other.seed, "space.json", jsonBytes(t, other.f.policy))
	gitCommand(t, other.seed, other.env, "add", "space.json")
	gitCommand(t, other.seed, other.env, "commit", "-m", "Initialize second synthetic identity")
	other.push(t, other.seed)
	a, _, _ := h.clone(t, "a")
	b, _, _ := other.clone(t, "b")
	mustWrite(t, a, h.op(t, "rec:a", h.f.writer.Identity()), h.f.writer)
	mustWrite(t, b, other.op(t, "rec:b", other.f.writer.Identity()), other.f.writer)
	views, e := space.ReadSpaces(context.Background(), []space.SpaceQuery{{Repository: b, Query: other.readQuery(t, b, other.f.writer.Identity())}, {Repository: a, Query: h.readQuery(t, a, h.f.writer.Identity())}})
	check(t, e)
	if len(views) != 2 || views[0].Space != "space:main" || views[1].Space != "space:second" {
		t.Fatal("space collection missing/determinism")
	}
	for _, v := range views {
		if v.View["data_classification"] != "data" || len(v.View["items"].([]any)) != 1 {
			t.Fatal("bad multi-space view")
		}
	}
	denied := nextPolicy(t, h, h.f.policy, func(p *space.Policy) { p.Readers = []space.Reader{} })
	h.seedAtRemote(t)
	rawCommit(t, h, h.seed, map[string][]byte{"space.json": jsonBytes(t, denied)}, nil)
	h.push(t, h.seed)
	check(t, a.Sync(context.Background()))
	_, e = a.Read(h.readQuery(t, a, h.f.writer.Identity()))
	errorIs(t, e, "not_authorized")
}

// TestGitExplainAndChanges proves the adapter invokes kernel explain and a
// persistent commit-bound changes capture, including refusal of an unknown cursor.
func TestGitExplainAndChanges(t *testing.T) {
	h := newGitHarness(t)
	repo, _, _ := h.clone(t, "reader")
	first := mustWrite(t, repo, h.op(t, "rec:a", h.f.writer.Identity()), h.f.writer)
	mustWrite(t, repo, h.op(t, "rec:b", h.f.writer.Identity()), h.f.writer)
	query := h.readQuery(t, repo, h.f.writer.Identity())
	query["kind"] = "explain"
	query["scope"].(map[string]any)["targets"] = []any{map[string]any{"id": "rec:a", "version": int64(1)}}
	view, e := repo.Read(query)
	check(t, e)
	if len(view["items"].([]any)) != 1 {
		t.Fatal("explain target missing")
	}
	query = h.readQuery(t, repo, h.f.writer.Identity())
	view, e = repo.ChangesSince(context.Background(), query, first.Commit)
	check(t, e)
	changes := view["changes"].(map[string]any)
	if changes["state"] != "changed" || len(changes["refs"].([]any)) != 1 {
		t.Fatalf("unexpected changes %+v", changes)
	}
	_, e = repo.ChangesSince(context.Background(), query, strings.Repeat("0", 40))
	errorIs(t, e, "invalid_cursor")
}

type countingSigner struct {
	*localkey.Key
	calls int
}

func (s *countingSigner) Sign(r sign.CanonicalRecord) (sign.Signature, error) {
	s.calls++
	return s.Key.Sign(r)
}

// TestGitScanAndDirtyClone refuses a planted synthetic token before any signature,
// file, commit or push; clean near-neighbour content then succeeds. It also proves
// unrelated dirty work is preserved and never staged by the library.
func TestGitScanAndDirtyClone(t *testing.T) {
	h := newGitHarness(t)
	repo, dir, _ := h.clone(t, "writer")
	check(t, repo.Sync(context.Background()))
	cursor := repo.Cursor()
	op := h.op(t, "rec:secret", h.f.writer.Identity())
	secret := "ghp_" + strings.Repeat("A", 36)
	op["proposals"].([]any)[0].(map[string]any)["body"].(map[string]any)["content"].([]any)[0].(map[string]any)["value"] = secret
	signer := &countingSigner{Key: h.f.writer}
	_, e := repo.Write(context.Background(), writeRequest(op, signer, 2))
	var scanError *space.ScanError
	if !errors.As(e, &scanError) || len(scanError.Findings) == 0 || signer.calls != 0 {
		t.Fatal("scanner failed before signing")
	}
	wire := string(jsonBytes(t, scanError))
	if strings.Contains(wire, secret) || repo.Cursor() != cursor {
		t.Fatal("scan leaked or wrote")
	}
	putFile(t, dir, "unrelated.txt", []byte("preserve"))
	_, e = repo.Write(context.Background(), writeRequest(h.op(t, "rec:a", h.f.writer.Identity()), signer, 2))
	errorIs(t, e, "dirty_clone")
	b, e := os.ReadFile(filepath.Join(dir, "unrelated.txt"))
	check(t, e)
	if string(b) != "preserve" {
		t.Fatal("foreign data changed")
	}
	check(t, os.Remove(filepath.Join(dir, "unrelated.txt")))
	mustWrite(t, repo, h.op(t, "rec:a", h.f.writer.Identity()), signer)
	if len(repo.Snapshot()["records"].([]any)) != 1 {
		t.Fatal("positive control refused")
	}
}

// TestGitMergedIndependentWrites admits non-conflicting side-branch writes at
// their first-parent merge position. The signed file retains its original local
// stamp while the evaluation index receives the replay cut; rebuilding agrees.
func TestGitMergedIndependentWrites(t *testing.T) {
	h := newGitHarness(t)
	a, aDir, _ := h.clone(t, "a")
	b, bDir, _ := h.clone(t, "b")
	check(t, b.Sync(context.Background()))
	files, tx := h.transactionFiles(t, b.Snapshot(), h.op(t, "rec:b", h.f.writer.Identity()), h.f.writer)
	bindTransactions(t, h, bDir, files, h.f.policy, tx)
	bHead := rawCommit(t, h, bDir, files, []map[string]any{tx})
	mustWrite(t, a, h.op(t, "rec:a", h.f.writer.Identity()), h.f.writer)
	gitCommand(t, aDir, h.env, "fetch", bDir, bHead)
	gitCommand(t, aDir, h.env, "merge", "--no-ff", "-m", "Merge independent synthetic writes", "FETCH_HEAD")
	h.push(t, aDir)
	check(t, a.Sync(context.Background()))
	check(t, b.Sync(context.Background()))
	if len(a.Snapshot()["records"].([]any)) != 2 || len(a.Diagnostics()) != 0 {
		t.Fatalf("independent merge failed: %+v", a.Diagnostics())
	}
	for path, expected := range files {
		got, e := os.ReadFile(filepath.Join(aDir, path))
		check(t, e)
		if !bytes.Equal(expected, got) {
			t.Fatal("signed bytes restamped on disk")
		}
	}
	x, _ := kernel.CanonicalJSON(a.Snapshot())
	y, _ := kernel.CanonicalJSON(b.Snapshot())
	if !bytes.Equal(x, y) {
		t.Fatal("merge replay differs")
	}
}

// TestGitMergedPolicyFork proves a secondary owner's valid competing policy
// cannot displace an already in-force first-parent policy even when git's merge
// resolution installs the secondary space.json. A later valid primary transition
// remains possible, so rejecting every policy does not satisfy this test.
func TestGitMergedPolicyFork(t *testing.T) {
	h := newGitHarness(t)
	a, aDir, _ := h.clone(t, "a")
	b, bDir, _ := h.clone(t, "b")
	check(t, a.Sync(context.Background()))
	check(t, b.Sync(context.Background()))
	first := nextPolicy(t, h, h.f.policy, func(p *space.Policy) { p.Writers = p.Writers[:1] })
	loser := nextPolicy(t, h, h.f.policy, func(p *space.Policy) { p.Limits.MaxFieldBytes = 7000 })
	bHead := rawCommit(t, h, bDir, map[string][]byte{"space.json": jsonBytes(t, loser)}, nil)
	rawCommit(t, h, aDir, map[string][]byte{"space.json": jsonBytes(t, first)}, nil)
	h.push(t, aDir)
	gitCommand(t, aDir, h.env, "fetch", bDir, bHead)
	gitCommand(t, aDir, h.env, "merge", "--no-ff", "-X", "theirs", "-m", "Merge competing signed policy", "FETCH_HEAD")
	h.push(t, aDir)
	check(t, a.Sync(context.Background()))
	check(t, b.Sync(context.Background()))
	expectDiagnostic(t, a, "policy_sequence")
	_, e := a.Write(context.Background(), writeRequest(h.op(t, "rec:second", h.second.Identity()), h.second, 1))
	errorIs(t, e, "grant_mismatch")
	winning := nextPolicy(t, h, first, func(p *space.Policy) { p.Writers = clone(t, h.f.policy.Policy.Writers) })
	rawCommit(t, h, aDir, map[string][]byte{"space.json": jsonBytes(t, winning)}, nil)
	h.push(t, aDir)
	mustWrite(t, a, h.op(t, "rec:second", h.second.Identity()), h.second)
	check(t, b.Sync(context.Background()))
	if len(b.Snapshot()["records"].([]any)) != 1 {
		t.Fatal("winning chain continuation refused")
	}
}

// TestGitTransactionBinding rejects altered metadata, a signed output inconsistent
// with kernel admission, cross-purpose signatures and invalid closed shape. A
// valid neighbour survives each case and signature checks never create authority.
func TestGitTransactionBinding(t *testing.T) {
	for _, kind := range []string{"metadata", "output", "purpose", "shape", "outer_shape"} {
		t.Run(kind, func(t *testing.T) {
			h := newGitHarness(t)
			repo, _, _ := h.clone(t, "reader")
			check(t, repo.Sync(context.Background()))
			files, good := h.transactionFiles(t, repo.Snapshot(), h.op(t, "rec:good", h.f.writer.Identity()), h.f.writer)
			badFiles, bad := h.transactionFiles(t, repo.Snapshot(), h.op(t, "rec:bad", h.f.writer.Identity()), h.f.writer)
			for path, b := range badFiles {
				files[path] = b
			}
			bindTransactions(t, h, h.seed, files, h.f.policy, bad, good)
			expected := "invalid_signature"
			switch kind {
			case "metadata":
				bad["write"].(map[string]any)["operation"].(map[string]any)["idempotency_key"] = "tampered"
			case "purpose":
				bad["signature"] = h.f.policy.Signature
				expected = "purpose_mismatch"
			case "outer_shape":
				bad["extra"] = true
				expected = "invalid_transaction"
			case "shape":
				bad["write"].(map[string]any)["extra"] = true
				expected = "invalid_shape"
			case "output":
				write := bad["write"].(map[string]any)
				record := write["records"].([]any)[0].(map[string]any)["record"].(map[string]any)
				record["body"].(map[string]any)["content"].([]any)[0].(map[string]any)["value"] = "different output"
				canonical, e := sign.NewCanonicalRecord(record, h.f.schemas, h.template["domain_schemas"].([]any))
				check(t, e)
				signature, e := h.f.writer.Sign(canonical)
				check(t, e)
				signed := sign.SignedRecord{Record: canonical, Signature: signature}
				wire := jsonBytes(t, signed)
				v, f := kernel.DecodeJSON(wire)
				if f != nil {
					t.Fatal(f)
				}
				write["records"] = []any{v}
				badFiles[space.RecordPath(canonical)] = wire
				request, e := sign.NewCanonicalWrite(write, h.f.schemas, h.template["domain_schemas"].([]any))
				check(t, e)
				signature, e = h.f.writer.SignWrite(request)
				check(t, e)
				bad["signature"] = signature
				expected = "admission_output_mismatch"
			}
			for path, b := range badFiles {
				files[path] = b
			}
			if kind == "output" {
				bindTransactions(t, h, h.seed, files, h.f.policy, bad, good)
			}
			rawCommit(t, h, h.seed, files, []map[string]any{bad, good})
			h.push(t, h.seed)
			check(t, repo.Sync(context.Background()))
			expectDiagnostic(t, repo, expected)
			if len(repo.Snapshot()["records"].([]any)) != 1 {
				t.Fatal("bad transaction or partial write admitted")
			}
			view, e := repo.Read(h.readQuery(t, repo, h.f.writer.Identity()))
			check(t, e)
			if len(view["items"].([]any)) != 1 {
				t.Fatal("valid control excluded")
			}
		})
	}
}

// TestWriteSignatureDomains proves the fourth purpose cannot replay into any of
// the existing three domains, nor the reverse, even after retagging. A complete
// write signs for its actor only, and its detached bytes cannot mutate the request.
func TestWriteSignatureDomains(t *testing.T) {
	h := newGitHarness(t)
	files, tx := h.transactionFiles(t, h.template, h.op(t, "rec:a", h.f.writer.Identity()), h.f.writer)
	_ = files
	write := tx["write"].(map[string]any)
	canonical, e := sign.NewCanonicalWrite(write, h.f.schemas, h.template["domain_schemas"].([]any))
	check(t, e)
	signature, e := h.f.writer.SignWrite(canonical)
	check(t, e)
	verifier := sign.Ed25519Verifier{}
	check(t, verifier.Verify(sign.WritePurpose, canonical.Bytes(), signature, h.f.writer.PublicKey()))
	_, e = h.second.SignWrite(canonical)
	diagnostic(t, e, sign.SubmitterMismatch)
	_, e = h.f.writer.SignWrite(sign.CanonicalWrite{})
	diagnostic(t, e, sign.SubmitterMismatch)
	wire := canonical.Bytes()
	wire[0] = '!'
	if canonical.Bytes()[0] == '!' {
		t.Fatal("write bytes alias")
	}
	policyCanonical, e := space.NewCanonicalPolicy(h.f.policy.Policy)
	check(t, e)
	registration := h.f.policy.Policy.Keys[0]
	registrationCanonical, e := space.NewCanonicalRegistration(registration.Registration)
	check(t, e)
	recordSignature, e := h.f.writer.Sign(h.f.record)
	check(t, e)
	for _, domain := range []struct {
		purpose   string
		body      []byte
		signature sign.Signature
		public    []byte
	}{
		{sign.RecordPurpose, h.f.record.Bytes(), recordSignature, h.f.writer.PublicKey()},
		{sign.PolicyPurpose, policyCanonical.Bytes(), h.f.policy.Signature, h.f.owner.PublicKey()},
		{sign.RegistrationPurpose, registrationCanonical.Bytes(), registration.Signature, h.f.owner.PublicKey()},
	} {
		check(t, verifier.Verify(domain.purpose, domain.body, domain.signature, domain.public))
		diagnostic(t, verifier.Verify(domain.purpose, canonical.Bytes(), signature, h.f.writer.PublicKey()), sign.PurposeMismatch)
		retag := signature
		retag.Purpose = domain.purpose
		diagnostic(t, verifier.Verify(domain.purpose, canonical.Bytes(), retag, h.f.writer.PublicKey()), sign.InvalidSignature)
		diagnostic(t, verifier.Verify(sign.WritePurpose, canonical.Bytes(), domain.signature, domain.public), sign.PurposeMismatch)
		retag = domain.signature
		retag.Purpose = sign.WritePurpose
		diagnostic(t, verifier.Verify(sign.WritePurpose, canonical.Bytes(), retag, domain.public), sign.InvalidSignature)
	}

}

// TestGitConfigurationBoundary rejects an inside-repository cache without making
// it, handles symlink aliases, and refuses malformed changes queries without panic.
func TestGitConfigurationBoundary(t *testing.T) {
	h := newGitHarness(t)
	repo, dir, _ := h.clone(t, "reader")
	config := space.Config{Git: space.Git{Directory: dir, Environment: h.env, UnsignedCommits: true}, CacheDirectory: filepath.Join(dir, "inside"), GenesisDigest: h.f.anchor, Template: h.template, Schemas: h.f.schemas, Mint: randomHandle}
	_, e := space.Open(config)
	errorIs(t, e, "cache_inside_repository")
	if _, e = os.Stat(config.CacheDirectory); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("rejected cache was created")
	}
	alias := filepath.Join(h.root, "alias")
	check(t, os.Symlink(dir, alias))
	config.CacheDirectory = filepath.Join(alias, "cache")
	_, e = space.Open(config)
	errorIs(t, e, "cache_inside_repository")
	check(t, repo.Sync(context.Background()))
	_, e = repo.ChangesSince(context.Background(), map[string]any{}, repo.Cursor())
	errorIs(t, e, "invalid_shape")
}

// TestGitReadAdmissionAuthority sends crypto-valid, granted revision requests
// directly through git. Wrong issuer and wrong expected version fail rules 4/5
// with their exact codes, while a valid same-commit neighbour remains readable.
func TestGitReadAdmissionAuthority(t *testing.T) {
	for _, wrongIssuer := range []bool{true, false} {
		t.Run(fmt.Sprint(wrongIssuer), func(t *testing.T) {
			h := newGitHarness(t)
			repo, _, _ := h.clone(t, "reader")
			mustWrite(t, repo, h.op(t, "rec:a", h.f.writer.Identity()), h.f.writer)
			issuer, actor := h.f.writer.Identity(), h.f.writer.Identity()
			signer := h.f.writer
			expected := "version_conflict"
			if wrongIssuer {
				issuer = h.second.Identity()
				actor = issuer
				signer = h.second
				expected = "representation_invalid"
			}
			op := h.revision(t, "rec:a", "rec:r1", issuer, actor, false)
			if !wrongIssuer {
				op["expected_version"].(map[string]any)["version"] = int64(9)
			}
			record := mapCopy(t, op["revision"].(map[string]any))
			env := record["envelope"].(map[string]any)
			env["submitter"] = actor
			env["admission_class"] = "machine_observation"
			env["recorded"] = map[string]any{"sequence": int64(102), "at": op["context"].(map[string]any)["at"]}
			canonical, e := sign.NewCanonicalRecord(record, h.f.schemas, h.template["domain_schemas"].([]any))
			check(t, e)
			signature, e := signer.Sign(canonical)
			check(t, e)
			signed := sign.SignedRecord{Record: canonical, Signature: signature}
			wire := jsonBytes(t, signed)
			value, f := kernel.DecodeJSON(wire)
			if f != nil {
				t.Fatal(f)
			}
			handle, e := randomHandle()
			check(t, e)
			write := map[string]any{"operation": op, "records": []any{value}, "receipt_handle": handle, "origin": h.initialOrigin(t)}
			request, e := sign.NewCanonicalWrite(write, h.f.schemas, h.template["domain_schemas"].([]any))
			check(t, e)
			signature, e = signer.SignWrite(request)
			check(t, e)
			files, good := h.transactionFiles(t, repo.Snapshot(), h.op(t, "rec:good", h.f.writer.Identity()), h.f.writer)
			files[space.RecordPath(canonical)] = wire
			h.seedAtRemote(t)
			bad := map[string]any{"write": write, "signature": signature}
			bindTransactions(t, h, h.seed, files, h.f.policy, bad, good)
			rawCommit(t, h, h.seed, files, []map[string]any{bad, good})
			h.push(t, h.seed)
			check(t, repo.Sync(context.Background()))
			expectDiagnostic(t, repo, expected)
			if len(repo.Snapshot()["records"].([]any)) != 2 {
				t.Fatal("invalid revision admitted or valid neighbour lost")
			}
			view, e := repo.Read(h.readQuery(t, repo, h.f.writer.Identity()))
			check(t, e)
			if len(view["items"].([]any)) != 2 {
				t.Fatal("invalid revision influenced evaluation")
			}
		})
	}
}
