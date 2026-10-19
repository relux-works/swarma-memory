package sign

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"

	"github.com/relux-works/swarma-memory/go/kernel"
)

const (
	RecordPurpose       = "swarma-memory-record/1"
	PolicyPurpose       = "swarma-memory-policy/1"
	RegistrationPurpose = "swarma-memory-key-registration/1"
)

type Code string

const (
	InvalidJSON          Code = "invalid_json"
	InvalidShape         Code = "invalid_shape"
	InvalidRecord        Code = "invalid_record"
	SubmitterMismatch    Code = "submitter_mismatch"
	PurposeMismatch      Code = "purpose_mismatch"
	InvalidAlgorithm     Code = "invalid_algorithm"
	InvalidSignature     Code = "invalid_signature"
	WrongKey             Code = "wrong_key"
	UnregisteredKey      Code = "unregistered_key"
	UnsignedRegistration Code = "unsigned_registration"
	InvalidRegistration  Code = "invalid_registration"
	UnauthorizedOwner    Code = "unauthorized_owner"
	InvalidPolicy        Code = "invalid_policy"
	PolicySequence       Code = "policy_sequence"
	PolicyAnchor         Code = "policy_anchor"
	GrantMismatch        Code = "grant_mismatch"
	SchemaNotAccepted    Code = "schema_not_accepted"
	SpaceMismatch        Code = "space_mismatch"
	LimitExceeded        Code = "limit_exceeded"
	SensitivityCeiling   Code = "sensitivity_ceiling"
	InvalidSnapshot      Code = "invalid_snapshot"
	KeyIO                Code = "key_io"
	InvalidKey           Code = "invalid_key"
	KeyPermissions       Code = "key_permissions"
)

// Diagnostic carries transport/trust failures separately from kernel refusals.
// Field is a fixed public field path, never rejected content or key material.
type Diagnostic struct {
	Code  Code
	Field string
}

func (d *Diagnostic) Error() string      { return string(d.Code) + ": " + d.Field }
func Fail(code Code, field string) error { return &Diagnostic{Code: code, Field: field} }

type Signature struct {
	Purpose string `json:"purpose"`
	Key     string `json:"key"`
	Alg     string `json:"alg"`
	Value   string `json:"value"`
}

type Signer interface {
	Sign(CanonicalRecord) (Signature, error)
}

// Verifier checks one purpose-separated signature. Registry/identity authority
// is supplied by space's verified policy, never inferred from a valid signature.
type Verifier interface {
	Verify(string, []byte, Signature, []byte) error
}
type Ed25519Verifier struct{}

func KeyID(public []byte) string {
	digest := sha256.Sum256(public)
	return "ed25519:sha256:" + hex.EncodeToString(digest[:])
}

// Frame is UTF-8 purpose, one NUL byte, then kernel canonical JSON bytes.
func Frame(purpose string, canonical []byte) []byte {
	return append(append([]byte(purpose), 0), canonical...)
}
func PolicyDigest(canonical []byte) string {
	d := sha256.Sum256(Frame(PolicyPurpose, canonical))
	return "sha256:" + hex.EncodeToString(d[:])
}
func (Ed25519Verifier) Verify(purpose string, canonical []byte, signature Signature, public []byte) error {
	if signature.Purpose != purpose {
		return Fail(PurposeMismatch, "signature.purpose")
	}
	if signature.Alg != "ed25519" {
		return Fail(InvalidAlgorithm, "signature.alg")
	}
	if len(public) != ed25519.PublicKeySize || signature.Key != KeyID(public) {
		return Fail(WrongKey, "signature.key")
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(signature.Value)
	if err != nil || len(raw) != ed25519.SignatureSize || base64.StdEncoding.EncodeToString(raw) != signature.Value || !ed25519.Verify(ed25519.PublicKey(public), Frame(purpose, canonical), raw) {
		return Fail(InvalidSignature, "signature.value")
	}
	return nil
}

// CanonicalRecord is an immutable validated full stored record. A zero value
// cannot be signed; Value and Bytes return detached copies.
type CanonicalRecord struct{ canonical string }

func NewCanonicalRecord(value any, schemas *kernel.Schemas, domains []any) (CanonicalRecord, error) {
	if r := schemas.ValidateStoredRecord(value, domains); r != nil {
		return CanonicalRecord{}, Fail(InvalidRecord, "record")
	}
	m, _ := value.(map[string]any)
	e, _ := m["envelope"].(map[string]any)
	if e["submitter"] == "" || e["id"] == "" || e["space"] == "" {
		return CanonicalRecord{}, Fail(InvalidRecord, "record.envelope")
	}
	b, r := kernel.CanonicalJSON(value)
	if r != nil {
		return CanonicalRecord{}, Fail(InvalidRecord, "record")
	}
	return CanonicalRecord{string(b)}, nil
}
func (r CanonicalRecord) Bytes() []byte { return []byte(r.canonical) }
func (r CanonicalRecord) Value() map[string]any {
	v, _ := kernel.DecodeJSON(r.Bytes())
	m, _ := v.(map[string]any)
	return m
}
func (r CanonicalRecord) Submitter() string {
	m := r.Value()
	e, _ := m["envelope"].(map[string]any)
	s, _ := e["submitter"].(string)
	return s
}
func (r CanonicalRecord) MarshalJSON() ([]byte, error) {
	if r.canonical == "" {
		return nil, Fail(InvalidRecord, "record")
	}
	return r.Bytes(), nil
}

type SignedRecord struct {
	Record    CanonicalRecord `json:"record"`
	Signature Signature       `json:"signature"`
}

// ParseRecord rejects duplicate keys, unknown fields and non-kernel JSON types.
func ParseRecord(data []byte, schemas *kernel.Schemas, domains []any) (SignedRecord, error) {
	value, r := kernel.DecodeJSON(data)
	if r != nil {
		return SignedRecord{}, Fail(InvalidJSON, "envelope")
	}
	m, ok := value.(map[string]any)
	if !ok || len(m) != 2 || m["record"] == nil {
		return SignedRecord{}, Fail(InvalidShape, "envelope")
	}
	sig, err := ParseSignature(m["signature"])
	if err != nil {
		return SignedRecord{}, err
	}
	if sig.Purpose != RecordPurpose {
		return SignedRecord{}, Fail(PurposeMismatch, "signature.purpose")
	}
	if sig.Alg != "ed25519" {
		return SignedRecord{}, Fail(InvalidAlgorithm, "signature.alg")
	}
	record, err := NewCanonicalRecord(m["record"], schemas, domains)
	if err != nil {
		return SignedRecord{}, err
	}
	return SignedRecord{record, sig}, nil
}
func ParseSignature(value any) (Signature, error) {
	m, ok := value.(map[string]any)
	if !ok || len(m) != 4 {
		return Signature{}, Fail(InvalidShape, "signature")
	}
	fields := []string{"purpose", "key", "alg", "value"}
	v := []string{}
	for _, k := range fields {
		s, ok := m[k].(string)
		if !ok {
			return Signature{}, Fail(InvalidShape, "signature."+k)
		}
		v = append(v, s)
	}
	return Signature{v[0], v[1], v[2], v[3]}, nil
}
