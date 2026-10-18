package sign

import (
	"strings"

	"github.com/relux-works/swarma-memory/kernel"
)

const WritePurpose = "swarma-memory-write/1"

// CanonicalWrite binds the full kernel request, its exact signed output files and
// its receipt handle and originating space, parent, tree and policy digest.
// Commit messages carry this envelope; record wire stays fixed.
// A signer sees the whole validated request and refuses another actor's identity.
type CanonicalWrite struct {
	canonical string
	actor     string
}

func (w CanonicalWrite) Bytes() []byte { return []byte(w.canonical) }
func (w CanonicalWrite) Actor() string { return w.actor }

// NewCanonicalWrite accepts a closed transaction object. Record signatures are
// verified by the space adapter against the historical policy, not by this parser.
func NewCanonicalWrite(value map[string]any, schemas *kernel.Schemas, domains []any) (CanonicalWrite, error) {
	if len(value) != 4 {
		return CanonicalWrite{}, Fail(InvalidShape, "write")
	}
	origin, ok := value["origin"].(map[string]any)
	if !ok || len(origin) != 4 {
		return CanonicalWrite{}, Fail(InvalidShape, "write.origin")
	}
	space, _ := origin["space"].(string)
	parent, _ := origin["parent"].(string)
	tree, _ := origin["tree"].(string)
	policy, _ := origin["policy"].(string)
	if space == "" || !writeHex(parent, 40) && !writeHex(parent, 64) || !writeHex(tree, len(parent)) || !strings.HasPrefix(policy, "sha256:") || !writeHex(strings.TrimPrefix(policy, "sha256:"), 64) {
		return CanonicalWrite{}, Fail(InvalidShape, "write.origin")
	}
	operation, ok := value["operation"].(map[string]any)
	if !ok {
		return CanonicalWrite{}, Fail(InvalidShape, "write.operation")
	}
	if r := schemas.ValidateWriteOperation(operation); r != nil {
		return CanonicalWrite{}, Fail(InvalidShape, "write.operation")
	}
	actor, _ := operation["context"].(map[string]any)["actor"].(string)
	handle, ok := value["receipt_handle"].(string)
	if actor == "" || !ok || len(handle) != 32 {
		return CanonicalWrite{}, Fail(InvalidShape, "write.receipt_handle")
	}
	for _, c := range handle {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return CanonicalWrite{}, Fail(InvalidShape, "write.receipt_handle")
		}
	}
	records, ok := value["records"].([]any)
	if !ok || len(records) == 0 {
		return CanonicalWrite{}, Fail(InvalidShape, "write.records")
	}
	for _, v := range records {
		b, r := kernel.CanonicalJSON(v)
		if r != nil {
			return CanonicalWrite{}, Fail(InvalidJSON, "write.records")
		}
		s, e := ParseRecord(b, schemas, domains)
		if e != nil {
			return CanonicalWrite{}, e
		}
		if s.Record.Submitter() != actor {
			return CanonicalWrite{}, Fail(SubmitterMismatch, "write.records")
		}
	}
	b, r := kernel.CanonicalJSON(value)
	if r != nil {
		return CanonicalWrite{}, Fail(InvalidJSON, "write")
	}
	return CanonicalWrite{string(b), actor}, nil
}

func writeHex(s string, length int) bool {
	if len(s) != length {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// WriteSigner authenticates transaction metadata in addition to each record.
type WriteSigner interface {
	Signer
	SignWrite(CanonicalWrite) (Signature, error)
}
