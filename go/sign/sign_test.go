package sign_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/relux-works/swarma-memory/go/sign"
)

// TestVerifierDiagnostics proves primitive verification distinguishes purpose,
// algorithm, public-key identity and signature failures beside a real valid pair.
// Canonical base64 is required even when decoding would ignore embedded newlines.
func TestVerifierDiagnostics(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	canonical := []byte(`{"value":"synthetic"}`)
	good := sign.Signature{Purpose: sign.RecordPurpose, Key: sign.KeyID(public), Alg: "ed25519", Value: base64.StdEncoding.EncodeToString(ed25519.Sign(private, append([]byte("swarma-memory-record/1\x00"), canonical...)))}
	verifier := sign.Ed25519Verifier{}
	for _, tc := range []struct {
		name   string
		want   sign.Code
		mutate func(*sign.Signature)
	}{
		{"purpose", sign.PurposeMismatch, func(s *sign.Signature) { s.Purpose = sign.PolicyPurpose }},
		{"algorithm", sign.InvalidAlgorithm, func(s *sign.Signature) { s.Alg = "other" }},
		{"key", sign.WrongKey, func(s *sign.Signature) { s.Key = "ed25519:sha256:unknown" }},
		{"signature length", sign.InvalidSignature, func(s *sign.Signature) { s.Value = "AA==" }},
		{"signature encoding", sign.InvalidSignature, func(s *sign.Signature) { s.Value = "not-base64" }},
		{"noncanonical encoding", sign.InvalidSignature, func(s *sign.Signature) { s.Value = s.Value[:4] + "\n" + s.Value[4:] }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := verifier.Verify(sign.RecordPurpose, canonical, good, public); err != nil {
				t.Fatal(err)
			}
			bad := good
			tc.mutate(&bad)
			err := verifier.Verify(sign.RecordPurpose, canonical, bad, public)
			var d *sign.Diagnostic
			if !errors.As(err, &d) || d.Code != tc.want {
				t.Fatalf("got %v; want %s", err, tc.want)
			}
		})
	}
}
