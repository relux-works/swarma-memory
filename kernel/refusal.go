package kernel

import "fmt"

// RefusalCode names one of the closed K-REF-1 outcomes.
type RefusalCode string

const (
	InvalidJSON              RefusalCode = "invalid_json"
	InvalidShape             RefusalCode = "invalid_shape"
	UnknownSchema            RefusalCode = "unknown_schema"
	UnknownProfile           RefusalCode = "unknown_profile"
	InvalidReference         RefusalCode = "invalid_reference"
	DuplicateRecord          RefusalCode = "duplicate_record"
	InvalidDomainValue       RefusalCode = "invalid_domain_value"
	InvalidTime              RefusalCode = "invalid_time"
	UnknownRule              RefusalCode = "unknown_rule"
	Cycle                    RefusalCode = "cycle"
	CrossScope               RefusalCode = "cross_scope"
	RepresentationInvalid    RefusalCode = "representation_invalid"
	NotAuthorized            RefusalCode = "not_authorized"
	Quarantined              RefusalCode = "quarantined"
	AuthorityReceiptRequired RefusalCode = "authority_receipt_required"
	VersionConflict          RefusalCode = "version_conflict"
	IdempotencyConflict      RefusalCode = "idempotency_conflict"
	RuleUnqualified          RefusalCode = "rule_unqualified"
	AssessmentKindInvalid    RefusalCode = "assessment_kind_invalid"
	ModeMismatch             RefusalCode = "mode_mismatch"
	LimitExceeded            RefusalCode = "limit_exceeded"
	PolicyMismatch           RefusalCode = "policy_mismatch"
	ErasureFenced            RefusalCode = "erasure_fenced"
	StaleGeneration          RefusalCode = "stale_generation"
	ErasureIncomplete        RefusalCode = "erasure_incomplete"
	DeclassificationInvalid  RefusalCode = "declassification_invalid"
	DisclosureRevoked        RefusalCode = "disclosure_revoked"
	PublicationStale         RefusalCode = "publication_stale"
	Unavailable              RefusalCode = "unavailable"
	ExecutionRequired        RefusalCode = "execution_required"
	UnsupportedOperation     RefusalCode = "unsupported_operation"
)

var refusalRetryable = map[RefusalCode]bool{
	InvalidJSON: false, InvalidShape: false, UnknownSchema: false,
	UnknownProfile: false, InvalidReference: false, DuplicateRecord: false,
	InvalidDomainValue: false, InvalidTime: false, UnknownRule: false,
	Cycle: false, CrossScope: false, RepresentationInvalid: false,
	NotAuthorized: false, Quarantined: false, AuthorityReceiptRequired: false,
	VersionConflict: true, IdempotencyConflict: false, RuleUnqualified: false,
	AssessmentKindInvalid: false, ModeMismatch: false, LimitExceeded: false,
	PolicyMismatch: true, ErasureFenced: false, StaleGeneration: true,
	ErasureIncomplete: true, DeclassificationInvalid: false, DisclosureRevoked: false,
	PublicationStale: true, Unavailable: true, ExecutionRequired: false,
	UnsupportedOperation: false,
}

// Refusal is exactly the K-REF-1 wire shape; retryable is fixed by the code.
type Refusal struct {
	Type      string      `json:"type"`
	Code      RefusalCode `json:"code"`
	Retryable bool        `json:"retryable"`
}

// NewRefusal constructs a known refusal and rejects codes outside K-REF-1.
func NewRefusal(code RefusalCode) (*Refusal, error) {
	if _, known := refusalRetryable[code]; !known {
		return nil, fmt.Errorf("unknown refusal code %q", code)
	}
	return refusal(code), nil
}

func refusal(code RefusalCode) *Refusal {
	return &Refusal{Type: "refusal", Code: code, Retryable: refusalRetryable[code]}
}

func (r *Refusal) Error() string { return string(r.Code) }
