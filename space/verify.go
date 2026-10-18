package space

import (
	"encoding/base64"
	"encoding/json"

	"github.com/relux-works/swarma-memory/kernel"
	"github.com/relux-works/swarma-memory/sign"
)

type registeredKey struct {
	identity string
	public   []byte
}

// VerifiedPolicy is immutable and can only be constructed by a complete,
// genesis-anchored chain check. Accessors return detached values.
type VerifiedPolicy struct {
	policy Policy
	digest string
	keys   map[string]registeredKey
}

func (p *VerifiedPolicy) Digest() string {
	if p == nil {
		return ""
	}
	return p.digest
}
func (p *VerifiedPolicy) Policy() Policy {
	if p == nil {
		return Policy{}
	}
	b, _ := json.Marshal(p.policy)
	var out Policy
	_ = json.Unmarshal(b, &out)
	return out
}

// VerifyChain requires a trusted out-of-band digest of the genesis policy body.
// Self-signing alone does not establish who owns a space. No partial chain is
// returned. The history adapter must authenticate the in-force version binding.
func VerifyChain(chain []SignedPolicy, genesisDigest string) ([]*VerifiedPolicy, error) {
	if len(chain) == 0 || !validDigest(genesisDigest) {
		return nil, sign.Fail(sign.PolicyAnchor, "genesis")
	}
	out := []*VerifiedPolicy{}
	var previous *VerifiedPolicy
	for _, signed := range chain {
		if signed.Signature.Purpose != sign.PolicyPurpose {
			return nil, sign.Fail(sign.PurposeMismatch, "signature.purpose")
		}
		canonical, err := NewCanonicalPolicy(signed.Policy)
		if err != nil {
			return nil, err
		}
		// Detach before retaining any caller-owned policy slices or pointers.
		var p Policy
		_ = json.Unmarshal(canonical.Bytes(), &p)
		digest := sign.PolicyDigest(canonical.Bytes())
		if previous == nil {
			if p.Version != 1 || p.Previous != nil {
				return nil, sign.Fail(sign.PolicySequence, "policy.version")
			}
			if digest != genesisDigest {
				return nil, sign.Fail(sign.PolicyAnchor, "genesis")
			}
		} else if p.Version != previous.policy.Version+1 || p.Previous == nil || *p.Previous != previous.digest || p.SpaceID != previous.policy.SpaceID || p.Kind != previous.policy.Kind {
			return nil, sign.Fail(sign.PolicySequence, "policy.previous")
		}
		keys := map[string]registeredKey{}
		for _, entry := range p.Keys {
			r := entry.Registration
			public, _ := base64.StdEncoding.Strict().DecodeString(r.PublicKey)
			keys[r.Key] = registeredKey{r.Identity, public}
		}
		authority := &VerifiedPolicy{policy: p, digest: digest, keys: keys}
		if previous != nil {
			authority = previous
		}
		verifyOwner := func(author string, purpose string, body []byte, sig sign.Signature) error {
			if !has(authority.policy.Owners, author) {
				return sign.Fail(sign.UnauthorizedOwner, "author")
			}
			k, ok := authority.keys[sig.Key]
			if !ok {
				return sign.Fail(sign.UnregisteredKey, "signature.key")
			}
			if k.identity != author {
				return sign.Fail(sign.WrongKey, "signature.key")
			}
			return (sign.Ed25519Verifier{}).Verify(purpose, body, sig, k.public)
		}
		if err := verifyOwner(p.Author, sign.PolicyPurpose, canonical.Bytes(), signed.Signature); err != nil {
			return nil, err
		}
		for _, entry := range p.Keys {
			request, err := NewCanonicalRegistration(entry.Registration)
			if err != nil {
				return nil, err
			}
			if err := verifyOwner(entry.Registration.Author, sign.RegistrationPurpose, request.Bytes(), entry.Signature); err != nil {
				return nil, err
			}
		}
		previous = &VerifiedPolicy{policy: p, digest: digest, keys: keys}
		out = append(out, previous)
	}
	return out, nil
}

// VerifyRecord implements architecture 6.3 rules 1–3 under this exact historical
// policy. It never derives policy authority from record-supplied timestamps.
func (p *VerifiedPolicy) VerifyRecord(signed sign.SignedRecord, schemas *kernel.Schemas, domains []any) (sign.CanonicalRecord, error) {
	if p == nil || p.keys == nil {
		return sign.CanonicalRecord{}, sign.Fail(sign.InvalidPolicy, "policy")
	}
	if signed.Signature.Purpose != sign.RecordPurpose {
		return sign.CanonicalRecord{}, sign.Fail(sign.PurposeMismatch, "signature.purpose")
	}
	k, ok := p.keys[signed.Signature.Key]
	if !ok {
		return sign.CanonicalRecord{}, sign.Fail(sign.UnregisteredKey, "signature.key")
	}
	if k.identity != signed.Record.Submitter() {
		return sign.CanonicalRecord{}, sign.Fail(sign.WrongKey, "signature.key")
	}
	if err := (sign.Ed25519Verifier{}).Verify(sign.RecordPurpose, signed.Record.Bytes(), signed.Signature, k.public); err != nil {
		return sign.CanonicalRecord{}, err
	}
	value := signed.Record.Value()
	e, _ := value["envelope"].(map[string]any)
	if e["space"] != p.policy.SpaceID {
		return sign.CanonicalRecord{}, sign.Fail(sign.SpaceMismatch, "record.envelope.space")
	}
	if e["schema"] != nil {
		ref, _ := e["schema"].(map[string]any)
		accepted := false
		for _, s := range p.policy.Schemas {
			if ref["id"] == s.ID && ref["version"] == s.Version {
				accepted = true
			}
		}
		if !accepted {
			return sign.CanonicalRecord{}, sign.Fail(sign.SchemaNotAccepted, "record.envelope.schema")
		}
	}
	record, err := sign.NewCanonicalRecord(value, schemas, domains)
	if err != nil {
		return sign.CanonicalRecord{}, err
	}
	granted := false
	for _, g := range p.policy.Writers {
		if g.Identity != record.Submitter() || !has(g.AdmissionClasses, e["admission_class"].(string)) || !has(g.Kinds, e["kind"].(string)) {
			continue
		}
		for _, s := range g.Schemas {
			if s == nil && e["schema"] == nil {
				granted = true
			}
			if s != nil {
				r, _ := e["schema"].(map[string]any)
				if r["id"] == s.ID && r["version"] == s.Version {
					granted = true
				}
			}
		}
	}
	if !granted {
		return sign.CanonicalRecord{}, sign.Fail(sign.GrantMismatch, "writers")
	}
	if int64(len(record.Bytes())) > p.policy.Limits.MaxRecordBytes || !fieldLimits(value["body"], p.policy.Limits.MaxFieldBytes) {
		return sign.CanonicalRecord{}, sign.Fail(sign.LimitExceeded, "limits")
	}
	disclosure, _ := e["disclosure"].(map[string]any)
	classes, _ := disclosure["field_classes"].([]any)
	for _, class := range classes {
		if class == "sensitive" {
			return sign.CanonicalRecord{}, sign.Fail(sign.SensitivityCeiling, "record.envelope.disclosure.field_classes")
		}
	}
	// Domain labels are independent of a submitter's chosen envelope labels.
	if e["kind"] == "assertion" {
		ref := e["schema"].(map[string]any)
		for _, raw := range domains {
			d := raw.(map[string]any)
			if d["id"] != ref["id"] || d["version"] != ref["version"] {
				continue
			}
			for _, field := range d["fields"].([]any) {
				f := field.(map[string]any)
				if f["disclosure_class"] != "sensitive" {
					continue
				}
				for _, content := range value["body"].(map[string]any)["content"].([]any) {
					if content.(map[string]any)["field"] == f["name"] {
						return sign.CanonicalRecord{}, sign.Fail(sign.SensitivityCeiling, "record.body.content")
					}
				}
			}
		}
	}
	return record, nil
}
func fieldLimits(value any, limit int64) bool {
	switch v := value.(type) {
	case string:
		b, _ := kernel.CanonicalJSON(v)
		return int64(len(b)) <= limit
	case []any:
		for _, x := range v {
			if !fieldLimits(x, limit) {
				return false
			}
		}
	case map[string]any:
		for k, x := range v {
			if k == "value" {
				b, _ := kernel.CanonicalJSON(x)
				if int64(len(b)) > limit {
					return false
				}
			}
			if !fieldLimits(x, limit) {
				return false
			}
		}
	}
	return true
}

// RecordAtPolicy binds a signed record to the policy in force at its admitted
// history position. The future history reader, not the record, supplies Policy.
type RecordAtPolicy struct {
	Record sign.SignedRecord
	Policy *VerifiedPolicy
}

// NewSnapshot adds trust verification to the kernel's complete snapshot boundary.
// The template must have an empty records array and trusted kernel intake/config
// metadata. No invalid record or partial state is returned. Admission authority
// and expected-version checks still belong to State.Write, not signatures.
func NewSnapshot(template map[string]any, records []RecordAtPolicy, schemas *kernel.Schemas, mint func() (string, error)) (*kernel.State, error) {
	encoded, r := kernel.CanonicalJSON(template)
	if r != nil {
		return nil, sign.Fail(sign.InvalidSnapshot, "template")
	}
	decoded, _ := kernel.DecodeJSON(encoded)
	snapshot, _ := decoded.(map[string]any)
	existing, ok := snapshot["records"].([]any)
	if !ok || len(existing) != 0 {
		return nil, sign.Fail(sign.InvalidSnapshot, "template.records")
	}
	domains, _ := snapshot["domain_schemas"].([]any)
	verified := []any{}
	for _, entry := range records {
		record, err := entry.Policy.VerifyRecord(entry.Record, schemas, domains)
		if err != nil {
			return nil, err
		}
		verified = append(verified, record.Value())
	}
	snapshot["records"] = verified
	state, refusal := kernel.NewState(snapshot, schemas, mint)
	if refusal != nil {
		return nil, sign.Fail(sign.InvalidSnapshot, "kernel."+string(refusal.Code))
	}
	return state, nil
}
