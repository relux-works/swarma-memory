// Package authored shares the purpose and author checks across signing backends.
// It is internal: only validated canonical objects reach the raw signing callback.
package authored

import (
	"github.com/relux-works/swarma-memory/go/sign"
	"github.com/relux-works/swarma-memory/go/space"
)

type Signer struct {
	Identity  string
	SignBytes func(string, []byte) (sign.Signature, error)
}

func (k Signer) Sign(record sign.CanonicalRecord) (sign.Signature, error) {
	if record.Submitter() == "" {
		return sign.Signature{}, sign.Fail(sign.InvalidRecord, "record")
	}
	if record.Submitter() != k.Identity {
		return sign.Signature{}, sign.Fail(sign.SubmitterMismatch, "record.envelope.submitter")
	}
	return k.SignBytes(sign.RecordPurpose, record.Bytes())
}
func (k Signer) SignPolicy(p space.CanonicalPolicy) (sign.Signature, error) {
	if p.Author() == "" {
		return sign.Signature{}, sign.Fail(sign.InvalidPolicy, "policy")
	}
	if p.Author() != k.Identity {
		return sign.Signature{}, sign.Fail(sign.SubmitterMismatch, "policy.author")
	}
	return k.SignBytes(sign.PolicyPurpose, p.Bytes())
}
func (k Signer) SignRegistration(r space.CanonicalRegistration) (sign.Signature, error) {
	if r.Author() == "" {
		return sign.Signature{}, sign.Fail(sign.InvalidRegistration, "registration")
	}
	if r.Author() != k.Identity {
		return sign.Signature{}, sign.Fail(sign.SubmitterMismatch, "registration.author")
	}
	return k.SignBytes(sign.RegistrationPurpose, r.Bytes())
}
func (k Signer) SignWrite(write sign.CanonicalWrite) (sign.Signature, error) {
	if k.Identity == "" || write.Actor() != k.Identity || len(write.Bytes()) == 0 {
		return sign.Signature{}, sign.Fail(sign.SubmitterMismatch, "write.operation.context.actor")
	}
	return k.SignBytes(sign.WritePurpose, write.Bytes())
}
func (k Signer) SignAdvertisement(p space.CanonicalAdvertisement) (sign.Signature, error) {
	if k.Identity == "" || p.Author() != k.Identity || len(p.Bytes()) == 0 {
		return sign.Signature{}, sign.Fail(sign.SubmitterMismatch, "advertisement.author")
	}
	return k.SignBytes(sign.AdvertisementPurpose, p.Bytes())
}
func (k Signer) SignDirectory(p space.CanonicalDirectory) (sign.Signature, error) {
	if k.Identity == "" || p.Author() != k.Identity || len(p.Bytes()) == 0 {
		return sign.Signature{}, sign.Fail(sign.SubmitterMismatch, "entry.author")
	}
	return k.SignBytes(sign.DirectoryPurpose, p.Bytes())
}
