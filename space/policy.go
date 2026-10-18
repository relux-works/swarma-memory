package space

import (
	"embed"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/relux-works/swarma-memory/kernel"
	"github.com/relux-works/swarma-memory/sign"
)

//go:embed schema/*.json
var schemaFiles embed.FS
var schemaOnce sync.Once
var policySchemas *kernel.Schemas

func schemas() *kernel.Schemas {
	schemaOnce.Do(func() { policySchemas, _ = kernel.LoadSchemas(schemaFiles) })
	return policySchemas
}

// Policy is the signed space.json payload. Metadata fields make transitions and
// author identity explicit; the history adapter supplies its in-force position.
type Policy struct {
	SpaceID   string               `json:"space_id"`
	Kind      string               `json:"kind"`
	Version   int64                `json:"version"`
	Previous  *string              `json:"previous"`
	Author    string               `json:"author"`
	Owners    []string             `json:"owners"`
	Writers   []Writer             `json:"writers"`
	Readers   []Reader             `json:"readers"`
	Keys      []SignedRegistration `json:"keys"`
	Schemas   []kernel.SchemaRef   `json:"schemas"`
	Ceiling   string               `json:"ceiling"`
	Limits    Limits               `json:"limits"`
	Resolvers []Resolver           `json:"resolvers"`
	Retention Retention            `json:"retention"`
}
type Writer struct {
	Identity         string              `json:"identity"`
	AdmissionClasses []string            `json:"admission_classes"`
	Schemas          []*kernel.SchemaRef `json:"schemas"`
	Kinds            []string            `json:"kinds"`
}
type Reader struct {
	Identity string   `json:"identity"`
	Spaces   []string `json:"spaces"`
}
type Limits struct {
	MaxRecordBytes int64 `json:"max_record_bytes"`
	MaxFieldBytes  int64 `json:"max_field_bytes"`
}
type Resolver struct {
	Area       string   `json:"area"`
	Identities []string `json:"identities"`
}
type Retention struct {
	OnOwnerRetire string `json:"on_owner_retire"`
	OnOwnerRevoke string `json:"on_owner_revoke"`
}
type Registration struct {
	SpaceID       string `json:"space_id"`
	PolicyVersion int64  `json:"policy_version"`
	Author        string `json:"author"`
	Identity      string `json:"identity"`
	Key           string `json:"key"`
	Alg           string `json:"alg"`
	PublicKey     string `json:"public_key"`
}
type SignedRegistration struct {
	Registration Registration   `json:"registration"`
	Signature    sign.Signature `json:"signature"`
}
type SignedPolicy struct {
	Policy    Policy         `json:"policy"`
	Signature sign.Signature `json:"signature"`
}

// CanonicalPolicy and CanonicalRegistration are detached, closed validated
// signing requests, never hashes or caller-owned mutable aliases.
type CanonicalPolicy struct {
	canonical string
	author    string
}
type CanonicalRegistration struct {
	canonical string
	author    string
}

func (p CanonicalPolicy) Bytes() []byte        { return []byte(p.canonical) }
func (p CanonicalPolicy) Author() string       { return p.author }
func (p CanonicalRegistration) Bytes() []byte  { return []byte(p.canonical) }
func (p CanonicalRegistration) Author() string { return p.author }

type PolicySigner interface {
	SignPolicy(CanonicalPolicy) (sign.Signature, error)
	SignRegistration(CanonicalRegistration) (sign.Signature, error)
}

func canonicalStruct(value any, schema string) ([]byte, error) {
	if !validText(reflect.ValueOf(value)) {
		return nil, sign.Fail(sign.InvalidJSON, "document")
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, sign.Fail(sign.InvalidShape, "document")
	}
	decoded, r := kernel.DecodeJSON(encoded)
	if r != nil {
		return nil, sign.Fail(sign.InvalidJSON, "document")
	}
	if r := schemas().Validate(decoded, "urn:bounded-evidence:space:1:"+schema); r != nil {
		return nil, sign.Fail(sign.InvalidShape, "document")
	}
	canonical, r := kernel.CanonicalJSON(decoded)
	if r != nil {
		return nil, sign.Fail(sign.InvalidJSON, "document")
	}
	return canonical, nil
}
func validText(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.String:
		return utf8.ValidString(v.String())
	case reflect.Ptr:
		if !v.IsNil() {
			return validText(v.Elem())
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if !validText(v.Field(i)) {
				return false
			}
		}
	case reflect.Slice:
		for i := 0; i < v.Len(); i++ {
			if !validText(v.Index(i)) {
				return false
			}
		}
	}
	return true
}
func NewCanonicalRegistration(r Registration) (CanonicalRegistration, error) {
	b, err := canonicalStruct(r, "registration")
	if err != nil {
		return CanonicalRegistration{}, err
	}
	pub, err := base64.StdEncoding.Strict().DecodeString(r.PublicKey)
	if err != nil || len(pub) != 32 || base64.StdEncoding.EncodeToString(pub) != r.PublicKey || r.Key != sign.KeyID(pub) || r.SpaceID == "" || r.Author == "" || r.Identity == "" || r.PolicyVersion < 1 {
		return CanonicalRegistration{}, sign.Fail(sign.InvalidRegistration, "keys.registration")
	}
	return CanonicalRegistration{string(b), r.Author}, nil
}
func NewCanonicalPolicy(p Policy) (CanonicalPolicy, error) {
	for _, entry := range p.Keys {
		if entry.Signature.Value == "" {
			return CanonicalPolicy{}, sign.Fail(sign.UnsignedRegistration, "keys.signature")
		}
	}
	b, err := canonicalStruct(p, "policy")
	if err != nil {
		return CanonicalPolicy{}, err
	}
	if p.SpaceID == "" || p.Author == "" || p.Version < 1 || !uniqueText(p.Owners, true) || p.Limits.MaxRecordBytes < 1 || p.Limits.MaxFieldBytes < 1 || p.Limits.MaxFieldBytes > p.Limits.MaxRecordBytes || p.Previous != nil && !validDigest(*p.Previous) {
		return CanonicalPolicy{}, sign.Fail(sign.InvalidPolicy, "policy")
	}
	refs := map[kernel.SchemaRef]bool{}
	for _, r := range p.Schemas {
		if r.ID == "" || r.Version < 1 || refs[r] {
			return CanonicalPolicy{}, sign.Fail(sign.InvalidPolicy, "schemas")
		}
		refs[r] = true
	}
	ids := map[string]bool{}
	for _, r := range p.Keys {
		if r.Signature.Value == "" {
			return CanonicalPolicy{}, sign.Fail(sign.UnsignedRegistration, "keys.signature")
		}
		if _, err := NewCanonicalRegistration(r.Registration); err != nil {
			return CanonicalPolicy{}, err
		}
		if r.Registration.SpaceID != p.SpaceID || r.Registration.PolicyVersion != p.Version || ids[r.Registration.Key] {
			return CanonicalPolicy{}, sign.Fail(sign.InvalidRegistration, "keys.registration")
		}
		ids[r.Registration.Key] = true
	}
	for _, owner := range p.Owners {
		found := false
		for _, r := range p.Keys {
			if r.Registration.Identity == owner {
				found = true
			}
		}
		if !found {
			return CanonicalPolicy{}, sign.Fail(sign.InvalidPolicy, "owners.keys")
		}
	}
	for _, w := range p.Writers {
		if w.Identity == "" || !uniqueText(w.AdmissionClasses, true) || !uniqueText(w.Kinds, true) || len(w.Schemas) == 0 {
			return CanonicalPolicy{}, sign.Fail(sign.InvalidPolicy, "writers")
		}
		seen := map[kernel.SchemaRef]bool{}
		null := false
		for _, r := range w.Schemas {
			if r == nil {
				if null {
					return CanonicalPolicy{}, sign.Fail(sign.InvalidPolicy, "writers.schemas")
				}
				null = true
				continue
			}
			if !refs[*r] || seen[*r] {
				return CanonicalPolicy{}, sign.Fail(sign.InvalidPolicy, "writers.schemas")
			}
			seen[*r] = true
		}
	}
	for _, r := range p.Readers {
		if r.Identity == "" || !uniqueText(r.Spaces, false) {
			return CanonicalPolicy{}, sign.Fail(sign.InvalidPolicy, "readers")
		}
	}
	for _, r := range p.Resolvers {
		if r.Area == "" || !uniqueText(r.Identities, true) {
			return CanonicalPolicy{}, sign.Fail(sign.InvalidPolicy, "resolvers")
		}
	}
	return CanonicalPolicy{string(b), p.Author}, nil
}
func uniqueText(a []string, nonempty bool) bool {
	if nonempty && len(a) == 0 {
		return false
	}
	seen := map[string]bool{}
	for _, s := range a {
		if s == "" || seen[s] {
			return false
		}
		seen[s] = true
	}
	return true
}
func has(a []string, s string) bool {
	for _, v := range a {
		if v == s {
			return true
		}
	}
	return false
}
func validDigest(s string) bool {
	if !strings.HasPrefix(s, "sha256:") || len(s) != 71 {
		return false
	}
	for _, c := range s[7:] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func ParsePolicy(data []byte) (SignedPolicy, error) {
	value, r := kernel.DecodeJSON(data)
	if r != nil {
		return SignedPolicy{}, sign.Fail(sign.InvalidJSON, "space.json")
	}
	m, _ := value.(map[string]any)
	p, _ := m["policy"].(map[string]any)
	keys, _ := p["keys"].([]any)
	for _, raw := range keys {
		k, _ := raw.(map[string]any)
		if k["signature"] == nil {
			return SignedPolicy{}, sign.Fail(sign.UnsignedRegistration, "keys.signature")
		}
	}
	sigmap, _ := m["signature"].(map[string]any)
	if purpose, ok := sigmap["purpose"].(string); ok && purpose != sign.PolicyPurpose {
		return SignedPolicy{}, sign.Fail(sign.PurposeMismatch, "signature.purpose")
	}
	if r := schemas().Validate(value, "urn:bounded-evidence:space:1:signed-policy"); r != nil {
		return SignedPolicy{}, sign.Fail(sign.InvalidShape, "space.json")
	}
	var out SignedPolicy
	if err := json.Unmarshal(data, &out); err != nil {
		return SignedPolicy{}, sign.Fail(sign.InvalidShape, "space.json")
	}
	if _, err := NewCanonicalPolicy(out.Policy); err != nil {
		return SignedPolicy{}, err
	}
	return out, nil
}
