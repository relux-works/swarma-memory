// Package sshagent signs memory frames through one explicitly configured Unix
// SSH agent. It never discovers sockets or handles private key material.
package sshagent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/relux-works/swarma-memory/go/sign"
	"github.com/relux-works/swarma-memory/go/sign/internal/authored"
	"github.com/relux-works/swarma-memory/go/space"
)

// MaxFrameBytes includes the four-byte SSH agent length header.
const MaxFrameBytes = 256 * 1024
const maxPayloadBytes = MaxFrameBytes - 4
const DefaultTimeout = 120 * time.Second
const keyType = "ssh-ed25519"

// Key contains only public configuration. Timeout applies to the complete
// preflight-and-sign attempt, including connection, reads and human approval.
type Key struct {
	identity, socket string
	public           ed25519.PublicKey
	timeout          time.Duration
}

func New(identity, socket string, public []byte, timeout time.Duration) (*Key, error) {
	if identity == "" || !utf8.ValidString(identity) || !filepath.IsAbs(socket) || !utf8.ValidString(socket) || strings.ContainsRune(socket, 0) || len(public) != ed25519.PublicKeySize || timeout < 0 {
		return nil, sign.Fail(sign.InvalidKey, "signer")
	}
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	return &Key{identity, socket, append(ed25519.PublicKey(nil), public...), timeout}, nil
}
func (k Key) String() string   { return "sshagent.Key(<redacted>)" }
func (k Key) GoString() string { return k.String() }
func (k *Key) Identity() string {
	if k == nil {
		return ""
	}
	return k.identity
}
func (k *Key) PublicKey() []byte {
	if k == nil {
		return nil
	}
	return append([]byte(nil), k.public...)
}
func (k *Key) ID() string { return sign.KeyID(k.PublicKey()) }
func (k *Key) Socket() string {
	if k == nil {
		return ""
	}
	return k.socket
}
func (k *Key) authored() authored.Signer {
	return authored.Signer{Identity: k.Identity(), SignBytes: k.sign}
}
func (k *Key) Sign(r sign.CanonicalRecord) (sign.Signature, error) { return k.authored().Sign(r) }
func (k *Key) SignPolicy(r space.CanonicalPolicy) (sign.Signature, error) {
	return k.authored().SignPolicy(r)
}
func (k *Key) SignRegistration(r space.CanonicalRegistration) (sign.Signature, error) {
	return k.authored().SignRegistration(r)
}
func (k *Key) SignWrite(r sign.CanonicalWrite) (sign.Signature, error) {
	return k.authored().SignWrite(r)
}
func (k *Key) SignAdvertisement(r space.CanonicalAdvertisement) (sign.Signature, error) {
	return k.authored().SignAdvertisement(r)
}
func (k *Key) SignDirectory(r space.CanonicalDirectory) (sign.Signature, error) {
	return k.authored().SignDirectory(r)
}

var _ sign.Signer = (*Key)(nil)
var _ sign.WriteSigner = (*Key)(nil)
var _ space.PolicySigner = (*Key)(nil)
var _ space.AdvertisementSigner = (*Key)(nil)
var _ space.DirectorySigner = (*Key)(nil)

// ParsePublicKey accepts one OpenSSH Ed25519 public line (optional comment),
// never authorized_keys options, multiple lines, certificates or private keys.
func ParsePublicKey(line string) ([]byte, error) {
	bad := sign.Fail(sign.InvalidKey, "public_key")
	line = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
	if len(line) > MaxFrameBytes || strings.ContainsAny(line, "\r\n\x00") || !utf8.ValidString(line) {
		return nil, bad
	}
	fields := strings.Fields(line)
	if len(fields) < 2 || fields[0] != keyType {
		return nil, bad
	}
	raw, e := base64.StdEncoding.Strict().DecodeString(fields[1])
	if e != nil || base64.StdEncoding.EncodeToString(raw) != fields[1] {
		return nil, bad
	}
	return parseKey(raw)
}
func blob(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = binary.BigEndian.AppendUint32(out, uint32(len(p)))
		out = append(out, p...)
	}
	return out
}
func publicBlob(public []byte) []byte { return blob([]byte(keyType), public) }

type decoder struct {
	data []byte
	bad  bool
}

func (d *decoder) uint32() uint32 {
	if len(d.data) < 4 {
		d.bad = true
		return 0
	}
	n := binary.BigEndian.Uint32(d.data)
	d.data = d.data[4:]
	return n
}
func (d *decoder) str() []byte {
	n := d.uint32()
	if d.bad || uint64(n) > uint64(len(d.data)) {
		d.bad = true
		return nil
	}
	out := d.data[:int(n)]
	d.data = d.data[int(n):]
	return out
}
func (d *decoder) done() bool { return !d.bad && len(d.data) == 0 }
func parseKey(b []byte) ([]byte, error) {
	d := decoder{data: b}
	typ := d.str()
	pub := d.str()
	if string(typ) != keyType || len(pub) != ed25519.PublicKeySize || !d.done() {
		return nil, sign.Fail(sign.InvalidKey, "public_key")
	}
	return append([]byte(nil), pub...), nil
}
func (k *Key) valid() bool {
	return k != nil && len(k.public) == ed25519.PublicKeySize && k.timeout > 0
}

// ProvePossession verifies a fresh, purpose-separated challenge against the
// configured public key. It returns no signature: the proof is transient and
// conveys key possession only, never policy authority or a publishable object.
func (k *Key) ProvePossession() error {
	if !k.valid() {
		return sign.Fail(sign.InvalidSignature, "signer")
	}
	var nonce [32]byte
	if _, e := rand.Read(nonce[:]); e != nil {
		return sign.Fail(sign.SignerUnavailable, "signer.challenge")
	}
	payload := append(nonce[:len(nonce):len(nonce)], []byte(k.Identity())...)
	payload = append(payload, []byte(k.ID())...)
	_, e := k.sign(sign.PossessionPurpose, payload)
	var diagnostic *sign.Diagnostic
	if errors.As(e, &diagnostic) && diagnostic.Code == sign.InvalidKey {
		return sign.Fail(sign.InvalidSignature, "signer.challenge")
	}
	return e
}

// Check requires exactly one matching identity. Unrelated Ed25519 identities
// are allowed, but malformed/unsupported entries and duplicate matches refuse.
func (k *Key) Check() error {
	if !k.valid() {
		return sign.Fail(sign.InvalidKey, "signer")
	}
	ctx, cancel := context.WithTimeout(context.Background(), k.timeout)
	defer cancel()
	return k.check(ctx)
}
func (k *Key) check(ctx context.Context) error {
	response, e := k.exchange(ctx, []byte{11}, sign.InvalidKey)
	if e != nil {
		return e
	}
	if response[0] != 12 {
		return sign.Fail(sign.InvalidKey, "agent.identities")
	}
	d := decoder{data: response[1:]}
	n := d.uint32()
	// Every entry contains at least two string lengths; bound iteration too.
	if d.bad || uint64(n) > uint64(len(d.data)/8) {
		return sign.Fail(sign.InvalidKey, "agent.identities")
	}
	matches := 0
	for i := uint32(0); i < n; i++ {
		b := d.str()
		_ = d.str()
		pub, e := parseKey(b)
		if e != nil || d.bad {
			return sign.Fail(sign.InvalidKey, "agent.identities")
		}
		if bytes.Equal(pub, k.public) {
			matches++
		}
	}
	if !d.done() || matches > 1 {
		return sign.Fail(sign.InvalidKey, "agent.identities")
	}
	if matches == 0 {
		return sign.Fail(sign.SignerKeyMissing, "signer.public_key")
	}
	return nil
}
func (k *Key) sign(purpose string, canonical []byte) (sign.Signature, error) {
	if !k.valid() {
		return sign.Signature{}, sign.Fail(sign.InvalidKey, "signer")
	}
	// Include the message type, two SSH strings and flags before allocating.
	if len(purpose) > MaxFrameBytes || len(canonical) > MaxFrameBytes || 1+8+len(publicBlob(k.public))+len(purpose)+1+len(canonical)+4 > maxPayloadBytes {
		return sign.Signature{}, sign.Fail(sign.InvalidSignature, "agent.frame")
	}
	ctx, cancel := context.WithTimeout(context.Background(), k.timeout)
	defer cancel()
	if e := k.check(ctx); e != nil {
		return sign.Signature{}, e
	}
	framed := sign.Frame(purpose, canonical)
	req := append([]byte{13}, blob(publicBlob(k.public), framed)...)
	req = binary.BigEndian.AppendUint32(req, 0)
	response, e := k.exchange(ctx, req, sign.InvalidSignature)
	if e != nil {
		return sign.Signature{}, e
	}
	if response[0] != 14 {
		return sign.Signature{}, sign.Fail(sign.InvalidSignature, "agent.signature")
	}
	outer := decoder{data: response[1:]}
	inner := decoder{data: outer.str()}
	typ := inner.str()
	raw := inner.str()
	if !outer.done() || !inner.done() {
		return sign.Signature{}, sign.Fail(sign.InvalidSignature, "agent.signature")
	}
	if string(typ) != keyType {
		return sign.Signature{}, sign.Fail(sign.InvalidKey, "agent.signature.type")
	}
	if len(raw) != ed25519.SignatureSize || !ed25519.Verify(k.public, framed, raw) {
		return sign.Signature{}, sign.Fail(sign.InvalidSignature, "agent.signature")
	}
	return sign.Signature{Purpose: purpose, Key: k.ID(), Alg: "ed25519", Value: base64.StdEncoding.EncodeToString(raw)}, nil
}

// exchange opens one connection per protocol operation, with no environment
// discovery, retry, TCP fallback or private material. RFC 9987 framing is bounded
// before allocation; each response parser must consume its entire payload.
func (k *Key) exchange(ctx context.Context, payload []byte, malformed sign.Code) ([]byte, error) {
	if len(payload) == 0 || len(payload) > maxPayloadBytes {
		return nil, sign.Fail(malformed, "agent.frame")
	}
	unavailable := sign.Fail(sign.SignerUnavailable, "signer.socket")
	dialer := net.Dialer{}
	conn, e := dialer.DialContext(ctx, "unix", k.socket)
	if e != nil {
		return nil, unavailable
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	if e = conn.SetDeadline(deadline); e != nil {
		return nil, unavailable
	}
	frame := binary.BigEndian.AppendUint32(nil, uint32(len(payload)))
	frame = append(frame, payload...)
	for len(frame) > 0 {
		n, e := conn.Write(frame)
		if e != nil || n == 0 {
			return nil, unavailable
		}
		frame = frame[n:]
	}
	var header [4]byte
	if _, e = io.ReadFull(conn, header[:]); e != nil {
		return nil, unavailable
	}
	n := binary.BigEndian.Uint32(header[:])
	if n == 0 || n > maxPayloadBytes {
		return nil, sign.Fail(malformed, "agent.frame")
	}
	response := make([]byte, int(n))
	if _, e = io.ReadFull(conn, response); e != nil {
		return nil, unavailable
	}
	if response[0] == 5 {
		if len(response) != 1 {
			return nil, sign.Fail(malformed, "agent.frame")
		}
		return nil, sign.Fail(sign.SignerRefused, "signer")
	}
	return response, nil
}
