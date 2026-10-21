package space_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/relux-works/swarma-memory/go/kernel"
	"github.com/relux-works/swarma-memory/go/sign"
	"github.com/relux-works/swarma-memory/go/space"
)

func resolverPolicy(t *testing.T) space.Policy {
	f := newFixture(t)
	p := f.policy.Policy
	space.UpgradeResolverPolicy(&p)
	p.Readers = append(p.Readers, space.Reader{Identity: f.writer.Identity(), Spaces: []string{}})
	return p
}
func resolverError(t *testing.T, p space.Policy, code string) {
	t.Helper()
	_, e := space.NewCanonicalPolicy(p)
	if e == nil || strings.Split(e.Error(), ":")[0] != code {
		t.Fatalf("got %v want %s", e, code)
	}
	// Parsing and verification independently enter policy validation, so a peer
	// cannot bypass the local signing refusal by supplying an external envelope.
	b, _ := json.Marshal(space.SignedPolicy{Policy: p, Signature: sign.Signature{Purpose: sign.PolicyPurpose, Key: "external", Alg: "ed25519", Value: "external"}})
	_, e = space.ParsePolicy(b)
	if e == nil || strings.Split(e.Error(), ":")[0] != code {
		t.Fatalf("parse got %v want %s", e, code)
	}
	_, e = space.VerifyChain([]space.SignedPolicy{{Policy: p, Signature: sign.Signature{Purpose: sign.PolicyPurpose}}}, "sha256:0000000000000000000000000000000000000000000000000000000000000000")
	if e == nil || strings.Split(e.Error(), ":")[0] != code {
		t.Fatalf("verify got %v want %s", e, code)
	}
}

// Exact matching ignores area prose and rejects both wildcard/intersection
// overlap directions; one fallback is allowed and cannot shadow a named route.
func TestResolverMatchingAndOverlap(t *testing.T) {
	p := resolverPolicy(t)
	id := p.Writers[0].Identity
	s := p.Schemas[0]
	named := space.Resolver{Area: "opaque * queue", Match: &space.ResolverMatch{Schemas: []kernel.SchemaRef{s}, Subjects: []string{"topic:queue"}}, Identities: []string{id}}
	fallback := space.Resolver{Area: "fallback", Match: &space.ResolverMatch{Schemas: []kernel.SchemaRef{}, Subjects: []string{}}, Identities: []string{id}}
	p.Resolvers = []space.Resolver{fallback, named}
	_, e := space.NewCanonicalPolicy(p)
	check(t, e)
	if got := p.RouteResolvers(s, "topic:queue"); got.Basis != "named" || got.Area == nil || *got.Area != named.Area {
		t.Fatal(got)
	}
	if p.RouteResolvers(s, "topic:queue:child").Basis != "catch_all" {
		t.Fatal("prefix matched")
	}
	for _, pair := range [][2]space.Resolver{{named, {Area: "other", Match: &space.ResolverMatch{Schemas: []kernel.SchemaRef{}, Subjects: []string{"topic:queue"}}, Identities: []string{id}}}, {named, {Area: "other", Match: &space.ResolverMatch{Schemas: []kernel.SchemaRef{s}, Subjects: []string{}}, Identities: []string{id}}}, {fallback, {Area: "other", Match: fallback.Match, Identities: []string{id}}}} {
		q := clone(t, p)
		q.Resolvers = []space.Resolver{pair[0], pair[1]}
		resolverError(t, q, "resolver_overlap")
		q.Resolvers = []space.Resolver{pair[1], pair[0]}
		resolverError(t, q, "resolver_overlap")
	}
	q := clone(t, p)
	q.Resolvers[1].Match.Subjects = []string{"topic:other"}
	q.Resolvers = append(q.Resolvers, named)
	q.Resolvers[2].Area = "disjoint"
	_, e = space.NewCanonicalPolicy(q)
	check(t, e)
	q.Resolvers = []space.Resolver{}
	got := q.RouteResolvers(s, "anything")
	if got.Basis != "default_owners" || !reflect.DeepEqual(got.Resolvers, p.Owners) {
		t.Fatal(got)
	}
}

// A listed identity needs its own key, reader and writer in the same policy;
// names and public reader grants convey no resolver qualification by themselves.
func TestResolverQualificationAndSchemas(t *testing.T) {
	p := resolverPolicy(t)
	p.Resolvers = []space.Resolver{{Area: "queue", Match: &space.ResolverMatch{Schemas: []kernel.SchemaRef{}, Subjects: []string{}}, Identities: []string{p.Writers[0].Identity}}}
	_, e := space.NewCanonicalPolicy(p)
	check(t, e)
	q := clone(t, p)
	q.Readers = []space.Reader{{Identity: "public", Spaces: []string{}}}
	resolverError(t, q, "resolver_unqualified")
	q = clone(t, p)
	q.Writers = []space.Writer{}
	resolverError(t, q, "resolver_unqualified")
	q = clone(t, p)
	q.Keys = q.Keys[:1]
	resolverError(t, q, "resolver_unqualified")
	q = clone(t, p)
	q.Resolvers[0].Match.Schemas = []kernel.SchemaRef{{ID: "schema:missing", Version: 1}}
	resolverError(t, q, "schema_not_accepted")
}

// Legacy signed bytes omit the discriminator and match. Multiple free-text
// entries route as a union catch-all and are upgraded only for a new signature.
func TestLegacyResolverUnion(t *testing.T) {
	f := newFixture(t)
	p := f.policy.Policy
	p.Resolvers = []space.Resolver{{Area: "queue", Identities: []string{"reader:b"}}, {Area: "not a classifier", Identities: []string{"reader:a", "reader:b"}}}
	canonical, e := space.NewCanonicalPolicy(p)
	check(t, e)
	var raw map[string]any
	json.Unmarshal(canonical.Bytes(), &raw)
	if raw["format"] != nil {
		t.Fatal("legacy bytes changed")
	}
	route := p.RouteResolvers(p.Schemas[0], "unrelated")
	if route.Basis != "catch_all" || route.Area != nil || !reflect.DeepEqual(route.Resolvers, []string{"reader:a", "reader:b"}) {
		t.Fatal(route)
	}
	if !reflect.DeepEqual(p.ResolverWarnings(), []string{"reader:a", "reader:b"}) {
		t.Fatal(p.ResolverWarnings())
	}
	space.UpgradeResolverPolicy(&p)
	if p.Format != space.PolicyFormatV2 || len(p.Resolvers) != 1 || p.Resolvers[0].Match == nil {
		t.Fatal(p)
	}
}

// Even a cryptographically valid owner signature over an overlapping candidate
// is refused by verification; the positive genesis with the same key succeeds.
func TestExternallySignedResolverOverlap(t *testing.T) {
	f := newFixture(t)
	p := resolverPolicy(t)
	id := p.Owners[0]
	pub, private, e := ed25519.GenerateKey(rand.Reader)
	check(t, e)
	rawSign := func(purpose string, b []byte) sign.Signature {
		return sign.Signature{Purpose: purpose, Key: sign.KeyID(pub), Alg: "ed25519", Value: base64.StdEncoding.EncodeToString(ed25519.Sign(private, sign.Frame(purpose, b)))}
	}
	reg := space.Registration{SpaceID: p.SpaceID, PolicyVersion: 1, Author: id, Identity: id, Key: sign.KeyID(pub), Alg: "ed25519", PublicKey: base64.StdEncoding.EncodeToString(pub)}
	request, e := space.NewCanonicalRegistration(reg)
	check(t, e)
	p.Keys = []space.SignedRegistration{{Registration: reg, Signature: rawSign(sign.RegistrationPurpose, request.Bytes())}}
	p.Readers = []space.Reader{{Identity: id, Spaces: []string{}}}
	p.Writers[0].Identity = id
	p.Resolvers = []space.Resolver{{Area: "one", Match: &space.ResolverMatch{Schemas: []kernel.SchemaRef{}, Subjects: []string{"topic:q"}}, Identities: []string{id}}}
	canonical, e := space.NewCanonicalPolicy(p)
	check(t, e)
	signed := space.SignedPolicy{Policy: p, Signature: rawSign(sign.PolicyPurpose, canonical.Bytes())}
	_, e = space.VerifyChain([]space.SignedPolicy{signed}, sign.PolicyDigest(canonical.Bytes()))
	check(t, e)
	p.Resolvers = append(p.Resolvers, space.Resolver{Area: "two", Match: p.Resolvers[0].Match, Identities: []string{id}})
	b, _ := json.Marshal(p)
	v, r := kernel.DecodeJSON(b)
	if r != nil {
		t.Fatal(r)
	}
	b, r = kernel.CanonicalJSON(v)
	if r != nil {
		t.Fatal(r)
	}
	sig := rawSign(sign.PolicyPurpose, b)
	check(t, (sign.Ed25519Verifier{}).Verify(sign.PolicyPurpose, b, sig, pub))
	_, e = space.VerifyChain([]space.SignedPolicy{{Policy: p, Signature: sig}}, sign.PolicyDigest(b))
	if e == nil || e.Error() != "resolver_overlap" {
		t.Fatal(e)
	}
	// The independently verified prior policy stays usable and routes as before.
	chain, e := space.VerifyChain([]space.SignedPolicy{signed}, sign.PolicyDigest(canonical.Bytes()))
	check(t, e)
	if chain[0].Policy().RouteResolvers(f.policy.Policy.Schemas[0], "topic:q").Basis != "named" {
		t.Fatal("previous routing lost")
	}
}

// In a qualified policy a local writer may resolve, while a registered foreign
// reader cannot. Duplicates/order/labels are policy constraints, not classifiers.
func TestQualifiedResolverAndCanonicalLists(t *testing.T) {
	f := newFixture(t)
	owner, foreign := key(t, "alpha/agent:owner"), key(t, "beta/agent:reader")
	p := resolverPolicy(t)
	p.Author, p.Owners = owner.Identity(), []string{owner.Identity()}
	p.Keys = []space.SignedRegistration{registration(t, owner, owner, p.SpaceID, 1), registration(t, owner, foreign, p.SpaceID, 1)}
	p.Readers = []space.Reader{{Identity: owner.Identity(), Spaces: []string{}}, {Identity: foreign.Identity(), Spaces: []string{}}}
	p.Writers = p.Writers[:1]
	p.Writers[0].Identity = owner.Identity()
	p.Resolvers = []space.Resolver{{Area: "local", Match: &space.ResolverMatch{Schemas: []kernel.SchemaRef{}, Subjects: []string{}}, Identities: []string{owner.Identity()}}}
	_, e := space.NewCanonicalPolicy(p)
	check(t, e)
	q := clone(t, p)
	q.Resolvers[0].Identities = []string{foreign.Identity()}
	resolverError(t, q, "resolver_unqualified")
	for _, mutate := range []func(*space.Policy){
		func(q *space.Policy) { q.Resolvers[0].Match.Subjects = []string{"z", "a"} },
		func(q *space.Policy) { q.Resolvers[0].Match.Subjects = []string{"a", "a"} },
		func(q *space.Policy) { q.Resolvers[0].Identities = []string{owner.Identity(), owner.Identity()} },
		func(q *space.Policy) { q.Resolvers[0].Match.Schemas = []kernel.SchemaRef{q.Schemas[0], q.Schemas[0]} },
		func(q *space.Policy) { q.Resolvers = append(q.Resolvers, q.Resolvers[0]) },
	} {
		q := clone(t, p)
		mutate(&q)
		resolverError(t, q, "invalid_policy")
	}
	// A legacy signed payload with free-text areas still round-trips exactly.
	legacy := f.policy.Policy
	legacy.Resolvers = []space.Resolver{{Area: "legacy prose", Identities: []string{"reader:legacy"}}}
	signed := signPolicy(t, f.owner, legacy)
	before, e := space.NewCanonicalPolicy(legacy)
	check(t, e)
	encoded, e := json.Marshal(signed)
	check(t, e)
	parsed, e := space.ParsePolicy(encoded)
	check(t, e)
	_, e = space.VerifyChain([]space.SignedPolicy{parsed}, sign.PolicyDigest(before.Bytes()))
	check(t, e)
	after, e := space.NewCanonicalPolicy(parsed.Policy)
	check(t, e)
	if string(before.Bytes()) != string(after.Bytes()) {
		t.Fatal("legacy signature payload changed")
	}
}
