package space_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"testing"
	"testing/fstest"

	"github.com/relux-works/swarma-memory/go/kernel"
	"github.com/relux-works/swarma-memory/go/sign"
	"github.com/relux-works/swarma-memory/go/sign/localkey"
	"github.com/relux-works/swarma-memory/go/space"
)

type fixture struct {
	schemas       *kernel.Schemas
	domains       []any
	record        sign.CanonicalRecord
	template      map[string]any
	owner, writer *localkey.Key
	policy        space.SignedPolicy
	verified      *space.VerifiedPolicy
	anchor        string
}

func check(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func diagnostic(t *testing.T, err error, want sign.Code) {
	t.Helper()
	var d *sign.Diagnostic
	if !errors.As(err, &d) || d.Code != want {
		t.Fatalf("got %v; want %s", err, want)
	}
}
func key(t *testing.T, identity string) *localkey.Key {
	t.Helper()
	k, e := localkey.Generate(identity)
	check(t, e)
	return k
}
func clone[T any](t *testing.T, v T) T {
	t.Helper()
	b, e := json.Marshal(v)
	check(t, e)
	var out T
	check(t, json.Unmarshal(b, &out))
	return out
}
func registration(t *testing.T, owner, subject *localkey.Key, spaceID string, version int64) space.SignedRegistration {
	t.Helper()
	r := space.Registration{SpaceID: spaceID, PolicyVersion: version, Author: owner.Identity(), Identity: subject.Identity(), Key: subject.ID(), Alg: "ed25519", PublicKey: base64.StdEncoding.EncodeToString(subject.PublicKey())}
	c, e := space.NewCanonicalRegistration(r)
	check(t, e)
	sig, e := owner.SignRegistration(c)
	check(t, e)
	return space.SignedRegistration{Registration: r, Signature: sig}
}
func signPolicy(t *testing.T, k *localkey.Key, p space.Policy) space.SignedPolicy {
	t.Helper()
	c, e := space.NewCanonicalPolicy(p)
	check(t, e)
	sig, e := k.SignPolicy(c)
	check(t, e)
	return space.SignedPolicy{Policy: p, Signature: sig}
}
func newFixture(t *testing.T) fixture {
	t.Helper()
	schemas, r := kernel.LoadSchemas(os.DirFS("../../spec/kernel/schemas"))
	if r != nil {
		t.Fatal(r)
	}
	b, e := os.ReadFile("../../spec/kernel/vectors/semantic/S14.json")
	check(t, e)
	v, r := kernel.DecodeJSON(b)
	if r != nil {
		t.Fatal(r)
	}
	doc := v.(map[string]any)
	initial := doc["initial_state"].(map[string]any)
	counter := 0
	state, r := kernel.NewState(initial, schemas, func() (string, error) { counter++; return fmt.Sprintf("%032x", counter), nil })
	if r != nil {
		t.Fatal(r)
	}
	if _, r = state.Write(doc["operations"].([]any)[0].(map[string]any)); r != nil {
		t.Fatal(r)
	}
	template := state.Snapshot()
	records := template["records"].([]any)
	domains := template["domain_schemas"].([]any)
	record, e := sign.NewCanonicalRecord(records[0], schemas, domains)
	check(t, e)
	template["records"] = []any{}
	envelope := record.Value()["envelope"].(map[string]any)
	ref := envelope["schema"].(map[string]any)
	schema := kernel.SchemaRef{ID: ref["id"].(string), Version: ref["version"].(int64)}
	owner, writer := key(t, "owner:synthetic"), key(t, record.Submitter())
	p := space.Policy{SpaceID: envelope["space"].(string), Kind: "project", Version: 1, Author: owner.Identity(), Owners: []string{owner.Identity()}, Writers: []space.Writer{{Identity: writer.Identity(), AdmissionClasses: []string{envelope["admission_class"].(string)}, Schemas: []*kernel.SchemaRef{&schema}, Kinds: []string{"assertion"}}}, Readers: []space.Reader{{Identity: "public", Spaces: []string{}}}, Keys: []space.SignedRegistration{registration(t, owner, owner, envelope["space"].(string), 1), registration(t, owner, writer, envelope["space"].(string), 1)}, Schemas: []kernel.SchemaRef{schema}, Ceiling: "non-sensitive", Limits: space.Limits{MaxRecordBytes: 65536, MaxFieldBytes: 8192}, Resolvers: []space.Resolver{}, Retention: space.Retention{OnOwnerRetire: "retain", OnOwnerRevoke: "deny"}}
	signed := signPolicy(t, owner, p)
	canonical, e := space.NewCanonicalPolicy(p)
	check(t, e)
	anchor := sign.PolicyDigest(canonical.Bytes())
	chain, e := space.VerifyChain([]space.SignedPolicy{signed}, anchor)
	check(t, e)
	return fixture{schemas, domains, record, template, owner, writer, signed, chain[0], anchor}
}
func (f fixture) signed(t *testing.T) sign.SignedRecord {
	t.Helper()
	sig, e := f.writer.Sign(f.record)
	check(t, e)
	return sign.SignedRecord{Record: f.record, Signature: sig}
}
func verifyGenesis(t *testing.T, p space.SignedPolicy) *space.VerifiedPolicy {
	t.Helper()
	c, e := space.NewCanonicalPolicy(p.Policy)
	check(t, e)
	chain, e := space.VerifyChain([]space.SignedPolicy{p}, sign.PolicyDigest(c.Bytes()))
	check(t, e)
	return chain[0]
}

// TestRecordRoundTrip proves real sign/serialize/strict parse/verify returns the
// exact canonical record; returned byte/tree/policy copies cannot alter authority.
func TestRecordRoundTrip(t *testing.T) {
	f := newFixture(t)
	signed := f.signed(t)
	wire, e := json.Marshal(signed)
	check(t, e)
	parsed, e := sign.ParseRecord(wire, f.schemas, f.domains)
	check(t, e)
	verified, e := f.verified.VerifyRecord(parsed, f.schemas, f.domains)
	check(t, e)
	if !bytes.Equal(f.record.Bytes(), verified.Bytes()) {
		t.Fatal("canonical record changed")
	}
	detached := verified.Value()
	detached["envelope"].(map[string]any)["submitter"] = "other"
	b := verified.Bytes()
	b[0] = 'x'
	policy := f.verified.Policy()
	policy.Writers[0].Identity = "other"
	policy.Keys[0].Registration.PublicKey = "other"
	_, e = f.verified.VerifyRecord(parsed, f.schemas, f.domains)
	check(t, e)
	pub := f.writer.PublicKey()
	pub[0] ^= 1
	if f.writer.ID() == sign.KeyID(pub) {
		t.Fatal("public key aliases signer")
	}
}

// TestRecordSignatureRefusals proves changed canonical content/signature, wrong
// identity key, unregistered keys and both purpose replays refuse specifically.
// Every subcase starts with a valid real-crypto verification control.
func TestRecordSignatureRefusals(t *testing.T) {
	for _, tc := range []struct {
		name   string
		want   sign.Code
		change func(*testing.T, fixture, *sign.SignedRecord)
	}{
		{"record byte", sign.InvalidSignature, func(t *testing.T, f fixture, s *sign.SignedRecord) {
			v := s.Record.Value()
			v["body"].(map[string]any)["content"].([]any)[0].(map[string]any)["value"] = "blpha"
			r, e := sign.NewCanonicalRecord(v, f.schemas, f.domains)
			check(t, e)
			s.Record = r
		}},
		{"signature byte", sign.InvalidSignature, func(t *testing.T, f fixture, s *sign.SignedRecord) {
			raw, e := base64.StdEncoding.DecodeString(s.Signature.Value)
			check(t, e)
			raw[0] ^= 1
			s.Signature.Value = base64.StdEncoding.EncodeToString(raw)
		}},
		{"wrong registered key", sign.WrongKey, func(t *testing.T, f fixture, s *sign.SignedRecord) { s.Signature.Key = f.owner.ID() }},
		{"unregistered key", sign.UnregisteredKey, func(t *testing.T, f fixture, s *sign.SignedRecord) {
			other := key(t, f.writer.Identity())
			sig, err := other.Sign(s.Record)
			check(t, err)
			check(t, (sign.Ed25519Verifier{}).Verify(sign.RecordPurpose, s.Record.Bytes(), sig, other.PublicKey()))
			s.Signature = sig
		}},
		{"policy signature as record", sign.PurposeMismatch, func(t *testing.T, f fixture, s *sign.SignedRecord) { s.Signature = f.policy.Signature }},
		{"retagged policy signature", sign.InvalidSignature, func(t *testing.T, f fixture, s *sign.SignedRecord) {
			s.Signature = f.policy.Signature
			s.Signature.Purpose = sign.RecordPurpose
			s.Signature.Key = f.writer.ID()
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			s := f.signed(t)
			_, e := f.verified.VerifyRecord(s, f.schemas, f.domains)
			check(t, e)
			tc.change(t, f, &s)
			_, e = f.verified.VerifyRecord(s, f.schemas, f.domains)
			diagnostic(t, e, tc.want)
		})
	}
	f := newFixture(t)
	bad := f.policy
	bad.Signature = f.signed(t).Signature
	_, e := space.VerifyChain([]space.SignedPolicy{bad}, f.anchor)
	diagnostic(t, e, sign.PurposeMismatch)
	_, e = f.owner.Sign(f.record)
	diagnostic(t, e, sign.SubmitterMismatch)
	_, e = f.writer.Sign(sign.CanonicalRecord{})
	diagnostic(t, e, sign.InvalidRecord)
	var nilKey *localkey.Key
	_, e = nilKey.Sign(f.record)
	diagnostic(t, e, sign.SubmitterMismatch)
}

// TestPolicyChain proves contiguous prior-owner authority, exact predecessor and
// a trusted genesis anchor; current owners cannot rewrite previous authority.
func TestPolicyChain(t *testing.T) {
	f := newFixture(t)
	p := f.verified.Policy()
	p.Version = 2
	p.Previous = &f.anchor
	for i, entry := range p.Keys {
		subject := f.writer
		if entry.Registration.Identity == f.owner.Identity() {
			subject = f.owner
		}
		p.Keys[i] = registration(t, f.owner, subject, p.SpaceID, 2)
	}
	second := signPolicy(t, f.owner, p)
	chain, e := space.VerifyChain([]space.SignedPolicy{f.policy, second}, f.anchor)
	check(t, e)
	if len(chain) != 2 || chain[1].Policy().Version != 2 {
		t.Fatal("chain lost version")
	}
	for _, tc := range []struct {
		name   string
		want   sign.Code
		change func(*space.Policy)
	}{
		{"skip", sign.PolicySequence, func(p *space.Policy) {
			p.Version = 3
			for i := range p.Keys {
				p.Keys[i].Registration.PolicyVersion = 3
				var e error
				c, err := space.NewCanonicalRegistration(p.Keys[i].Registration)
				check(t, err)
				p.Keys[i].Signature, e = f.owner.SignRegistration(c)
				check(t, e)
			}
		}},
		{"wrong previous", sign.PolicySequence, func(p *space.Policy) {
			wrong := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			p.Previous = &wrong
		}},
		{"non-owner author", sign.UnauthorizedOwner, func(p *space.Policy) { p.Author = f.writer.Identity(); p.Owners = []string{f.writer.Identity()} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := clone(t, p)
			tc.change(&bad)
			signer := f.owner
			if bad.Author == f.writer.Identity() {
				signer = f.writer
			}
			candidate := signPolicy(t, signer, bad)
			_, err := space.VerifyChain([]space.SignedPolicy{f.policy, candidate}, f.anchor)
			diagnostic(t, err, tc.want)
		})
	}
	_, e = space.VerifyChain([]space.SignedPolicy{f.policy}, "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	diagnostic(t, e, sign.PolicyAnchor)
	_, e = space.VerifyChain(nil, f.anchor)
	diagnostic(t, e, sign.PolicyAnchor)
	// A new owner's key must be endorsed by the previous owner, then may sign v3.
	rotated := clone(t, p)
	rotated.Owners = []string{f.writer.Identity()}
	rotation := signPolicy(t, f.owner, rotated)
	chain, e = space.VerifyChain([]space.SignedPolicy{f.policy, rotation}, f.anchor)
	check(t, e)
	third := chain[1].Policy()
	third.Version = 3
	previous := chain[1].Digest()
	third.Previous = &previous
	third.Author = f.writer.Identity()
	for i, entry := range third.Keys {
		subject := f.writer
		if entry.Registration.Identity == f.owner.Identity() {
			subject = f.owner
		}
		third.Keys[i] = registration(t, f.writer, subject, third.SpaceID, 3)
	}
	_, e = space.VerifyChain([]space.SignedPolicy{f.policy, rotation, signPolicy(t, f.writer, third)}, f.anchor)
	check(t, e)
	// The removed owner cannot sign another transition even with its still-registered key.
	third.Author = f.owner.Identity()
	_, e = space.VerifyChain([]space.SignedPolicy{f.policy, rotation, signPolicy(t, f.owner, third)}, f.anchor)
	diagnostic(t, e, sign.UnauthorizedOwner)
}

// TestOwnerEndorsements proves registration membership alone is insufficient;
// absent, forged, foreign-space and non-owner endorsements cannot mint authority.
func TestOwnerEndorsements(t *testing.T) {
	for _, tc := range []struct {
		name   string
		want   sign.Code
		change func(*testing.T, fixture, *space.Policy)
	}{
		{"unsigned", sign.UnsignedRegistration, func(t *testing.T, f fixture, p *space.Policy) { p.Keys[1].Signature = sign.Signature{} }},
		{"forged owner signature", sign.InvalidSignature, func(t *testing.T, f fixture, p *space.Policy) {
			raw, e := base64.StdEncoding.DecodeString(p.Keys[1].Signature.Value)
			check(t, e)
			raw[0] ^= 1
			p.Keys[1].Signature.Value = base64.StdEncoding.EncodeToString(raw)
		}},
		{"non-owner", sign.UnauthorizedOwner, func(t *testing.T, f fixture, p *space.Policy) {
			p.Keys[1] = registration(t, f.writer, f.writer, p.SpaceID, 1)
		}},
		{"foreign space", sign.InvalidRegistration, func(t *testing.T, f fixture, p *space.Policy) {
			p.Keys[1] = registration(t, f.owner, f.writer, "space:other", 1)
		}},
		{"wrong version", sign.InvalidRegistration, func(t *testing.T, f fixture, p *space.Policy) {
			p.Keys[1] = registration(t, f.owner, f.writer, p.SpaceID, 2)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			_, e := f.verified.VerifyRecord(f.signed(t), f.schemas, f.domains)
			check(t, e)
			p := clone(t, f.policy.Policy)
			tc.change(t, f, &p)
			c, e := space.NewCanonicalPolicy(p)
			if e == nil {
				sig, err := f.owner.SignPolicy(c)
				check(t, err)
				_, e = space.VerifyChain([]space.SignedPolicy{{Policy: p, Signature: sig}}, sign.PolicyDigest(c.Bytes()))
			}
			diagnostic(t, e, tc.want)
		})
	}
}

// TestWriterGrants proves class/schema/kind must match one complete grant, and
// accepted schemas, space and configured size bounds are enforced independently.
func TestWriterGrants(t *testing.T) {
	for _, tc := range []struct {
		name   string
		want   sign.Code
		change func(*space.Policy)
	}{
		{"class", sign.GrantMismatch, func(p *space.Policy) { p.Writers[0].AdmissionClasses = []string{"semantic_inference"} }},
		{"schema", sign.GrantMismatch, func(p *space.Policy) {
			other := kernel.SchemaRef{ID: "schema:other", Version: 1}
			p.Schemas = append(p.Schemas, other)
			p.Writers[0].Schemas = []*kernel.SchemaRef{&other}
		}},
		{"kind", sign.GrantMismatch, func(p *space.Policy) { p.Writers[0].Kinds = []string{"assessment"} }},
		{"null schema is explicit", sign.GrantMismatch, func(p *space.Policy) { p.Writers[0].Schemas = []*kernel.SchemaRef{nil} }},
		{"identity", sign.GrantMismatch, func(p *space.Policy) { p.Writers[0].Identity = p.Owners[0] }},
		{"unaccepted schema", sign.SchemaNotAccepted, func(p *space.Policy) { p.Schemas = []kernel.SchemaRef{}; p.Writers = []space.Writer{} }},
		{"record limit", sign.LimitExceeded, func(p *space.Policy) { p.Limits = space.Limits{MaxRecordBytes: 100, MaxFieldBytes: 100} }},
		{"field limit", sign.LimitExceeded, func(p *space.Policy) { p.Limits.MaxFieldBytes = 3 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			_, e := f.verified.VerifyRecord(f.signed(t), f.schemas, f.domains)
			check(t, e)
			p := clone(t, f.policy.Policy)
			tc.change(&p)
			vp := verifyGenesis(t, signPolicy(t, f.owner, p))
			_, e = vp.VerifyRecord(f.signed(t), f.schemas, f.domains)
			diagnostic(t, e, tc.want)
		})
	}
}

// TestSnapshotAdapter proves only fully verified records enter a complete valid
// kernel snapshot; bad signatures, domain values and unsigned template records
// return no partial state, while valid canonical bytes survive integration.
func TestSnapshotAdapter(t *testing.T) {
	f := newFixture(t)
	bound := []space.RecordAtPolicy{{Record: f.signed(t), Policy: f.verified}}
	state, e := space.NewSnapshot(f.template, bound, f.schemas, nil)
	check(t, e)
	b, r := kernel.CanonicalJSON(state.Snapshot()["records"].([]any)[0])
	if r != nil || !bytes.Equal(b, f.record.Bytes()) {
		t.Fatal("adapter changed record")
	}
	bad := append([]space.RecordAtPolicy(nil), bound...)
	bad[0].Record.Signature.Value = "bad"
	before, _ := kernel.CanonicalJSON(f.template)
	state, e = space.NewSnapshot(f.template, bad, f.schemas, nil)
	diagnostic(t, e, sign.InvalidSignature)
	if state != nil {
		t.Fatal("partial state")
	}
	after, _ := kernel.CanonicalJSON(f.template)
	if !bytes.Equal(before, after) {
		t.Fatal("template mutated")
	}
	template := cloneJSON(t, f.template)
	template["records"] = []any{f.record.Value()}
	state, e = space.NewSnapshot(template, bound, f.schemas, nil)
	diagnostic(t, e, sign.InvalidSnapshot)
	if state != nil {
		t.Fatal("unsigned template accepted")
	}
	// A same-ID domain with an incompatible required field still fails rule 2.
	domains := cloneJSON(t, map[string]any{"domains": f.domains})["domains"].([]any)
	for _, raw := range domains {
		d := raw.(map[string]any)
		if d["id"] == "schema:assumption" {
			d["fields"].([]any)[0].(map[string]any)["type"] = "integer"
		}
	}
	_, e = f.verified.VerifyRecord(f.signed(t), f.schemas, domains)
	diagnostic(t, e, sign.InvalidRecord)
}
func cloneJSON(t *testing.T, v map[string]any) map[string]any {
	t.Helper()
	b, r := kernel.CanonicalJSON(v)
	if r != nil {
		t.Fatal(r)
	}
	out, r := kernel.DecodeJSON(b)
	if r != nil {
		t.Fatal(r)
	}
	return out.(map[string]any)
}

// TestClosedWireSchemas proves published transport schemas accept real envelopes
// and reject unknown fields, with strict parsers also rejecting duplicate keys.
func TestClosedWireSchemas(t *testing.T) {
	f := newFixture(t)
	files := fstest.MapFS{}
	for _, dir := range []string{"../../spec/kernel/schemas", "../sign/schema", "schema"} {
		check(t, fs.WalkDir(os.DirFS(dir), ".", func(name string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				return nil
			}
			b, e := fs.ReadFile(os.DirFS(dir), name)
			if e != nil {
				return e
			}
			files[fmt.Sprintf("%d.json", len(files))] = &fstest.MapFile{Data: b}
			return nil
		}))
	}
	schemas, r := kernel.LoadSchemas(files)
	if r != nil {
		t.Fatal(r)
	}
	for _, tc := range []struct {
		name, id string
		wire     any
	}{{"record", "urn:bounded-evidence:sign:1:signed-record", f.signed(t)}, {"policy", "urn:bounded-evidence:space:1:signed-policy", f.policy}} {
		b, e := json.Marshal(tc.wire)
		check(t, e)
		v, r := kernel.DecodeJSON(b)
		if r != nil {
			t.Fatal(r)
		}
		if r = schemas.Validate(v, tc.id); r != nil {
			t.Fatal(r)
		}
		var objects []map[string]any
		var collect func(any)
		collect = func(node any) {
			switch x := node.(type) {
			case map[string]any:
				objects = append(objects, x)
				for _, child := range x {
					collect(child)
				}
			case []any:
				for _, child := range x {
					collect(child)
				}
			}
		}
		collect(v)
		for _, object := range objects {
			object["unexpected"] = true
			if r = schemas.Validate(v, tc.id); r == nil {
				t.Fatal("nested closed-schema control accepted", tc.name)
			}
			delete(object, "unexpected")
		}
		v.(map[string]any)["unexpected"] = true
		if r = schemas.Validate(v, tc.id); r == nil {
			t.Fatal("schema accepted unknown field", tc.name)
		}
		bad, _ := kernel.CanonicalJSON(v)
		if tc.name == "record" {
			_, e = sign.ParseRecord(bad, f.schemas, f.domains)
		} else {
			_, e = space.ParsePolicy(bad)
		}
		diagnostic(t, e, sign.InvalidShape)
	}
	b, e := json.Marshal(f.policy)
	check(t, e)
	parsed, e := space.ParsePolicy(b)
	check(t, e)
	_, e = space.VerifyChain([]space.SignedPolicy{parsed}, f.anchor)
	check(t, e)
	_, e = space.ParsePolicy([]byte(`{"policy":{},"policy":{}}`))
	diagnostic(t, e, sign.InvalidJSON)
	_, e = sign.ParseRecord([]byte(`{"record":{},"record":{}}`), f.schemas, f.domains)
	diagnostic(t, e, sign.InvalidJSON)
}

// TestFramingIndependentCrypto proves the documented NUL framing against direct
// stdlib Ed25519, and rejects an otherwise valid signature without that separator.
func TestFramingIndependentCrypto(t *testing.T) {
	public, private, e := ed25519.GenerateKey(rand.Reader)
	check(t, e)
	canonical := []byte(`{"value":"synthetic"}`)
	message := append([]byte("swarma-memory-record/1\x00"), canonical...)
	sig := sign.Signature{Purpose: sign.RecordPurpose, Key: sign.KeyID(public), Alg: "ed25519", Value: base64.StdEncoding.EncodeToString(ed25519.Sign(private, message))}
	check(t, (sign.Ed25519Verifier{}).Verify(sign.RecordPurpose, canonical, sig, public))
	sig.Value = base64.StdEncoding.EncodeToString(ed25519.Sign(private, append([]byte(sign.RecordPurpose), canonical...)))
	diagnostic(t, (sign.Ed25519Verifier{}).Verify(sign.RecordPurpose, canonical, sig, public), sign.InvalidSignature)
	diagnostic(t, (sign.Ed25519Verifier{}).Verify(sign.PolicyPurpose, canonical, sig, public), sign.PurposeMismatch)
}

// TestHistoricalKeyRotation proves old keys remain valid only under their exact
// historical policy; a new owner-endorsed key cannot borrow the previous policy.
func TestHistoricalKeyRotation(t *testing.T) {
	f := newFixture(t)
	newKey := key(t, f.writer.Identity())
	p := f.verified.Policy()
	p.Version = 2
	p.Previous = &f.anchor
	p.Keys = []space.SignedRegistration{registration(t, f.owner, f.owner, p.SpaceID, 2), registration(t, f.owner, newKey, p.SpaceID, 2)}
	next := signPolicy(t, f.owner, p)
	chain, e := space.VerifyChain([]space.SignedPolicy{f.policy, next}, f.anchor)
	check(t, e)
	old := f.signed(t)
	_, e = chain[0].VerifyRecord(old, f.schemas, f.domains)
	check(t, e)
	_, e = chain[1].VerifyRecord(old, f.schemas, f.domains)
	diagnostic(t, e, sign.UnregisteredKey)
	sig, e := newKey.Sign(f.record)
	check(t, e)
	current := sign.SignedRecord{Record: f.record, Signature: sig}
	_, e = chain[1].VerifyRecord(current, f.schemas, f.domains)
	check(t, e)
	_, e = chain[0].VerifyRecord(current, f.schemas, f.domains)
	diagnostic(t, e, sign.UnregisteredKey)
}

// TestNonAssertionGrants proves null is an explicit non-domain grant selector;
// a source needs its own class/kind tuple, with no borrowing from assertions.
func TestNonAssertionGrants(t *testing.T) {
	f := newFixture(t)
	b, e := os.ReadFile("../../spec/kernel/vectors/semantic/S30.json")
	check(t, e)
	v, r := kernel.DecodeJSON(b)
	if r != nil {
		t.Fatal(r)
	}
	var record sign.CanonicalRecord
	for _, raw := range v.(map[string]any)["initial_state"].(map[string]any)["records"].([]any) {
		m := raw.(map[string]any)
		if m["envelope"].(map[string]any)["kind"] == "source" {
			record, e = sign.NewCanonicalRecord(raw, f.schemas, f.domains)
			check(t, e)
			break
		}
	}
	writer := key(t, record.Submitter())
	p := f.verified.Policy()
	p.Keys = []space.SignedRegistration{registration(t, f.owner, f.owner, p.SpaceID, 1), registration(t, f.owner, writer, p.SpaceID, 1)}
	class := record.Value()["envelope"].(map[string]any)["admission_class"].(string)
	p.Writers = []space.Writer{{Identity: writer.Identity(), AdmissionClasses: []string{class}, Schemas: []*kernel.SchemaRef{nil}, Kinds: []string{"source"}}}
	vp := verifyGenesis(t, signPolicy(t, f.owner, p))
	sig, e := writer.Sign(record)
	check(t, e)
	signed := sign.SignedRecord{Record: record, Signature: sig}
	_, e = vp.VerifyRecord(signed, f.schemas, f.domains)
	check(t, e)
	p.Writers[0].Schemas = []*kernel.SchemaRef{&p.Schemas[0]}
	vp = verifyGenesis(t, signPolicy(t, f.owner, p))
	_, e = vp.VerifyRecord(signed, f.schemas, f.domains)
	diagnostic(t, e, sign.GrantMismatch)
}

// TestMalformedTrustValues proves ordinary malformed public inputs and zero
// values fail with diagnostics, never panics or partially verified results.
func TestMalformedTrustValues(t *testing.T) {
	f := newFixture(t)
	for _, raw := range []string{`null`, `[]`, `{}`, `{"record":{}}`, `{"record":{},"signature":null}`, `{"record":{},"signature":{"purpose":"swarma-memory-record/1","key":"x","alg":"ed25519","value":"x"}}`} {
		_, e := sign.ParseRecord([]byte(raw), f.schemas, f.domains)
		if e == nil {
			t.Fatal("malformed record accepted")
		}
	}
	for _, raw := range []string{`null`, `[]`, `{}`, `{"policy":{}}`} {
		_, e := space.ParsePolicy([]byte(raw))
		if e == nil {
			t.Fatal("malformed policy accepted")
		}
	}
	_, e := sign.NewCanonicalRecord(nil, f.schemas, f.domains)
	diagnostic(t, e, sign.InvalidRecord)
	_, e = sign.NewCanonicalRecord(f.record.Value(), nil, f.domains)
	diagnostic(t, e, sign.InvalidRecord)
	var absent *space.VerifiedPolicy
	_, e = absent.VerifyRecord(f.signed(t), f.schemas, f.domains)
	diagnostic(t, e, sign.InvalidPolicy)
	_, e = f.writer.SignPolicy(space.CanonicalPolicy{})
	diagnostic(t, e, sign.InvalidPolicy)
	_, e = f.writer.SignRegistration(space.CanonicalRegistration{})
	diagnostic(t, e, sign.InvalidRegistration)
	p := clone(t, f.policy.Policy)
	p.Keys = append(p.Keys, p.Keys[1])
	_, e = space.NewCanonicalPolicy(p)
	diagnostic(t, e, sign.InvalidRegistration)
	p = clone(t, f.policy.Policy)
	p.Limits.MaxFieldBytes = 0
	_, e = space.NewCanonicalPolicy(p)
	diagnostic(t, e, sign.InvalidPolicy)
	p = clone(t, f.policy.Policy)
	p.Owners = append(p.Owners, p.Owners[0])
	_, e = space.NewCanonicalPolicy(p)
	diagnostic(t, e, sign.InvalidPolicy)
	p = clone(t, f.policy.Policy)
	p.Author = string([]byte{0xff})
	_, e = space.NewCanonicalPolicy(p)
	diagnostic(t, e, sign.InvalidJSON)
}

// TestGrantTuplesAndCeiling proves grants cannot be assembled from disjoint
// tuples and neither explicit nor domain-declared sensitive fields fit git's
// ceiling. Public records under their complete original grant are the control.
func TestGrantTuplesAndCeiling(t *testing.T) {
	f := newFixture(t)
	_, e := f.verified.VerifyRecord(f.signed(t), f.schemas, f.domains)
	check(t, e)
	p := f.verified.Policy()
	first := clone(t, p.Writers[0])
	second := clone(t, first)
	first.Kinds = []string{"source"}
	second.AdmissionClasses = []string{"semantic_inference"}
	p.Writers = []space.Writer{first, second}
	vp := verifyGenesis(t, signPolicy(t, f.owner, p))
	_, e = vp.VerifyRecord(f.signed(t), f.schemas, f.domains)
	diagnostic(t, e, sign.GrantMismatch)
	value := f.record.Value()
	value["envelope"].(map[string]any)["space"] = "space:other"
	record, e := sign.NewCanonicalRecord(value, f.schemas, f.domains)
	check(t, e)
	sig, e := f.writer.Sign(record)
	check(t, e)
	_, e = f.verified.VerifyRecord(sign.SignedRecord{Record: record, Signature: sig}, f.schemas, f.domains)
	diagnostic(t, e, sign.SpaceMismatch)
	value = f.record.Value()
	value["envelope"].(map[string]any)["disclosure"].(map[string]any)["field_classes"] = []any{"sensitive"}
	record, e = sign.NewCanonicalRecord(value, f.schemas, f.domains)
	check(t, e)
	sig, e = f.writer.Sign(record)
	check(t, e)
	_, e = f.verified.VerifyRecord(sign.SignedRecord{Record: record, Signature: sig}, f.schemas, f.domains)
	diagnostic(t, e, sign.SensitivityCeiling)
	domains := cloneJSON(t, map[string]any{"domains": f.domains})["domains"].([]any)
	for _, raw := range domains {
		d := raw.(map[string]any)
		if d["id"] == "schema:assumption" {
			d["fields"].([]any)[0].(map[string]any)["disclosure_class"] = "sensitive"
		}
	}
	_, e = f.verified.VerifyRecord(f.signed(t), f.schemas, domains)
	diagnostic(t, e, sign.SensitivityCeiling)
}
