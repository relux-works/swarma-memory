package sshagent

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/relux-works/swarma-memory/go/sign"
	"github.com/relux-works/swarma-memory/go/space"
)

type fake struct {
	release        chan struct{}
	mu             sync.Mutex
	mode           string
	public         ed25519.PublicKey
	private, other ed25519.PrivateKey
	socket         string
	listener       net.Listener
	stop           chan struct{}
	done           chan struct{}
	requests       int
	frames         [][]byte
}

func newFake(t *testing.T) *fake {
	t.Helper()
	pub, priv, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	_, other, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	dir, e := os.MkdirTemp("", "a-")
	if e != nil {
		t.Fatal(e)
	}
	f := &fake{release: make(chan struct{}), public: pub, private: priv, other: other, socket: filepath.Join(dir, "s"), stop: make(chan struct{}), done: make(chan struct{})}
	f.listener, e = net.Listen("unix", f.socket)
	if e != nil {
		os.RemoveAll(dir)
		t.Fatal(e)
	}
	go func() {
		defer close(f.done)
		for {
			c, e := f.listener.Accept()
			if e != nil {
				return
			}
			f.serve(c)
		}
	}()
	t.Cleanup(func() {
		close(f.stop)
		f.listener.Close()
		<-f.done
		os.RemoveAll(dir)
		if c, e := net.DialTimeout("unix", f.socket, 50*time.Millisecond); e == nil {
			c.Close()
			t.Error("fixture listener survived")
		}
	})
	return f
}
func (f *fake) set(mode string) { f.mu.Lock(); defer f.mu.Unlock(); f.mode = mode }
func (f *fake) serve(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	var h [4]byte
	if _, e := io.ReadFull(c, h[:]); e != nil {
		return
	}
	n := binary.BigEndian.Uint32(h[:])
	if n < 1 || n > MaxFrameBytes {
		return
	}
	request := make([]byte, int(n))
	if _, e := io.ReadFull(c, request); e != nil {
		return
	}
	f.mu.Lock()
	mode := f.mode
	f.requests++
	f.mu.Unlock()
	if mode == "hang" || mode == "sign-hang" && request[0] == 13 {
		select {
		case <-f.stop:
		case <-f.release:
		}
		return
	}
	var response []byte
	if request[0] == 11 {
		if len(request) != 1 {
			return
		}
		keys := [][]byte{publicBlob(f.public)}
		switch mode {
		case "empty":
			keys = nil
		case "different":
			keys = [][]byte{publicBlob(f.other.Public().(ed25519.PublicKey))}
		case "duplicate":
			keys = append(keys, keys[0])
		case "nonkey":
			keys = [][]byte{blob([]byte("ssh-rsa"), []byte{1})}
		}
		response = binary.BigEndian.AppendUint32([]byte{12}, uint32(len(keys)))
		for _, k := range keys {
			response = append(response, blob(k, []byte("fixture"))...)
		}
		if mode == "max-identities" {
			response = binary.BigEndian.AppendUint32([]byte{12}, 1)
			response = append(response, blob(publicBlob(f.public), make([]byte, maxPayloadBytes-5-8-len(publicBlob(f.public))))...)
		}

		if mode == "identities-trailing" {
			response = append(response, 0)
		}
	} else if request[0] == 13 {
		d := decoder{data: request[1:]}
		key := d.str()
		framed := d.str()
		flags := d.uint32()
		if !d.done() || flags != 0 || !bytes.Equal(key, publicBlob(f.public)) {
			return
		}
		f.mu.Lock()
		f.frames = append(f.frames, append([]byte(nil), framed...))
		f.mu.Unlock()
		private := f.private
		if mode == "wrong" {
			private = f.other
		}
		raw := ed25519.Sign(private, framed)
		typ := keyType
		switch mode {
		case "non-type":
			typ = "ssh-rsa"
		case "short-sig":
			raw = raw[:63]
		case "bad-signature":
			raw[0] ^= 1
		}
		inner := blob([]byte(typ), raw)
		if mode == "inner-trailing" {
			inner = append(inner, 0)
		}
		response = append([]byte{14}, blob(inner)...)
		if mode == "trailing" {
			response = append(response, 0)
		}
	} else {
		return
	}
	if mode == "failure" || mode == "sign-failure" && request[0] == 13 {
		response = []byte{5}
	}
	if mode == "failure-trailing" {
		response = []byte{5, 0}
	}
	if strings.HasPrefix(mode, "sign-") {
		if request[0] == 13 {
			mode = strings.TrimPrefix(mode, "sign-")
		} else {
			mode = ""
		}
	}

	if mode == "zero" {
		_, _ = c.Write([]byte{0, 0, 0, 0})
		return
	}
	if mode == "oversize" {
		_, _ = c.Write(binary.BigEndian.AppendUint32(nil, MaxFrameBytes+1))
		return
	}
	if mode == "truncated-header" {
		_, _ = c.Write([]byte{0, 0})
		return
	}
	frame := binary.BigEndian.AppendUint32(nil, uint32(len(response)))
	frame = append(frame, response...)
	if mode == "truncated" {
		frame = frame[:len(frame)-1]
	}
	_, _ = c.Write(frame)
}
func expectCode(t *testing.T, e error, want sign.Code) {
	t.Helper()
	var d *sign.Diagnostic
	if !errors.As(e, &d) || d.Code != want {
		t.Fatalf("got %v want %s", e, want)
	}
}

// Every malformed/unsupported/refused response fails with a zero signature;
// fixing the same explicit endpoint permits a locally verified retry. Only this
// fixture's ephemeral key is used; each protocol operation uses a fresh socket.
func TestAgentProtocolAndRetry(t *testing.T) {
	for _, tc := range []struct {
		mode string
		want sign.Code
	}{
		{"empty", sign.SignerKeyMissing}, {"different", sign.SignerKeyMissing}, {"duplicate", sign.InvalidKey}, {"nonkey", sign.InvalidKey},
		{"failure", sign.SignerRefused}, {"sign-failure", sign.SignerRefused}, {"wrong", sign.InvalidSignature}, {"bad-signature", sign.InvalidSignature},
		{"non-type", sign.InvalidKey}, {"short-sig", sign.InvalidSignature}, {"trailing", sign.InvalidSignature}, {"inner-trailing", sign.InvalidSignature},
		{"identities-trailing", sign.InvalidKey}, {"truncated", sign.SignerUnavailable}, {"truncated-header", sign.SignerUnavailable},
		{"sign-oversize", sign.InvalidSignature}, {"sign-zero", sign.InvalidSignature}, {"sign-truncated", sign.SignerUnavailable}, {"sign-truncated-header", sign.SignerUnavailable}, {"oversize", sign.InvalidKey}, {"zero", sign.InvalidKey}, {"failure-trailing", sign.InvalidKey},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			f := newFake(t)
			k, e := New("owner", f.socket, f.public, time.Second)
			if e != nil {
				t.Fatal(e)
			}
			f.set(tc.mode)
			sig, e := k.sign(sign.RecordPurpose, []byte(`{"a":1}`))
			expectCode(t, e, tc.want)
			if sig != (sign.Signature{}) {
				t.Fatal("bad signature escaped")
			}
			f.set("")
			sig, e = k.sign(sign.RecordPurpose, []byte(`{"a":1}`))
			if e != nil {
				t.Fatal(e)
			}
			if e = (sign.Ed25519Verifier{}).Verify(sign.RecordPurpose, []byte(`{"a":1}`), sig, f.public); e != nil {
				t.Fatal(e)
			}
		})
	}
}

// The configured timeout bounds an unresponsive explicit agent. A missing or
// non-listening socket never falls back to SSH_AUTH_SOCK; good explicit signing
// still succeeds even when the ambient socket is a different working agent.
func TestAgentDeadlineAndNoFallback(t *testing.T) {
	f := newFake(t)
	ambient := newFake(t)
	t.Setenv("SSH_AUTH_SOCK", ambient.socket)
	k, e := New("owner", f.socket, f.public, 40*time.Millisecond)
	if e != nil {
		t.Fatal(e)
	}
	f.set("hang")
	start := time.Now()
	_, e = k.sign(sign.PolicyPurpose, []byte("{}"))
	expectCode(t, e, sign.SignerUnavailable)
	if time.Since(start) < 30*time.Millisecond || time.Since(start) > time.Second {
		t.Fatal("deadline not bounded")
	}
	missing, e := New("owner", f.socket+"missing", f.public, time.Second)
	if e != nil {
		t.Fatal(e)
	}
	expectCode(t, missing.Check(), sign.SignerUnavailable)
	closed := filepath.Join(filepath.Dir(f.socket), "closed")
	l, e := net.Listen("unix", closed)
	if e != nil {
		t.Fatal(e)
	}
	l.(*net.UnixListener).SetUnlinkOnClose(false)
	l.Close()
	missing.socket = closed
	expectCode(t, missing.Check(), sign.SignerUnavailable)
	close(f.release)
	f.set("")
	k.timeout = time.Second
	if _, e = k.sign(sign.RecordPurpose, []byte("{}")); e != nil {
		t.Fatal(e)
	}
	signHang := newFake(t)
	signHang.set("sign-hang")
	deadlineKey, e := New("owner", signHang.socket, signHang.public, 40*time.Millisecond)
	if e != nil {
		t.Fatal(e)
	}
	_, e = deadlineKey.sign(sign.RecordPurpose, []byte("{}"))
	expectCode(t, e, sign.SignerUnavailable)
	close(signHang.release)
	signHang.set("")
	deadlineKey.timeout = time.Second
	if _, e = deadlineKey.sign(sign.RecordPurpose, []byte("{}")); e != nil {
		t.Fatal(e)
	}

	ambient.mu.Lock()
	defer ambient.mu.Unlock()
	if ambient.requests != 0 {
		t.Fatal("ambient agent touched")
	}
}

// Canonical source validation and author mismatches refuse before any socket
// request for all six interfaces. CLI controls exercise valid objects separately.
func TestAuthoredInterfaces(t *testing.T) {
	f := newFake(t)
	k, e := New("owner", f.socket, f.public, time.Second)
	if e != nil {
		t.Fatal(e)
	}
	_, e = k.Sign(sign.CanonicalRecord{})
	expectCode(t, e, sign.InvalidRecord)
	_, e = k.SignPolicy(space.CanonicalPolicy{})
	expectCode(t, e, sign.InvalidPolicy)
	_, e = k.SignRegistration(space.CanonicalRegistration{})
	expectCode(t, e, sign.InvalidRegistration)
	_, e = k.SignWrite(sign.CanonicalWrite{})
	expectCode(t, e, sign.SubmitterMismatch)
	_, e = k.SignAdvertisement(space.CanonicalAdvertisement{})
	expectCode(t, e, sign.SubmitterMismatch)
	_, e = k.SignDirectory(space.CanonicalDirectory{})
	expectCode(t, e, sign.SubmitterMismatch)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.requests != 0 {
		t.Fatal("invalid canonical value reached agent")
	}
}

// Public parsing is strict about algorithm, sizes, complete blobs and canonical
// base64. Configuration copies public bytes; formatting exposes no configuration.
func TestPublicKeysAndBounds(t *testing.T) {
	f := newFake(t)
	valid := "ssh-ed25519 " + base64.StdEncoding.EncodeToString(publicBlob(f.public)) + " comment\n"
	pub, e := ParsePublicKey(valid)
	if e != nil || !bytes.Equal(pub, f.public) {
		t.Fatal(e)
	}
	for _, line := range []string{"", "ssh-rsa AAAA", valid + valid, "no " + valid, "ssh-ed25519 " + base64.StdEncoding.EncodeToString(append(publicBlob(pub), 0)), "ssh-ed25519 " + base64.StdEncoding.EncodeToString(blob([]byte(keyType), pub[:31]))} {
		_, e := ParsePublicKey(line)
		expectCode(t, e, sign.InvalidKey)
	}
	for _, socket := range []string{"", "relative", "/bad\x00path"} {
		_, e := New("owner", socket, pub, 0)
		expectCode(t, e, sign.InvalidKey)
	}
	_, e = New("", f.socket, pub, 0)
	expectCode(t, e, sign.InvalidKey)
	_, e = New("owner", f.socket, pub, -time.Second)
	expectCode(t, e, sign.InvalidKey)
	k, e := New("owner", f.socket, pub, 0)
	if e != nil || k.timeout != DefaultTimeout {
		t.Fatal(e)
	}
	pub[0] ^= 1
	copyPub := k.PublicKey()
	copyPub[0] ^= 1
	if !bytes.Equal(k.PublicKey(), f.public) {
		t.Fatal("public bytes alias")
	}
	for _, v := range []string{fmt.Sprint(k), fmt.Sprintf("%#v", k), fmt.Sprintf("%+v", *k)} {
		if strings.Contains(v, f.socket) || !strings.Contains(v, "redacted") {
			t.Fatal(v)
		}
	}
	_, e = k.sign(sign.RecordPurpose, make([]byte, MaxFrameBytes))
	expectCode(t, e, sign.InvalidSignature)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.requests != 0 {
		t.Fatal("oversize input reached agent")
	}
}

// Bounds are inclusive for complete frames; one extra request byte fails before
// any connection. Signatures equal ordinary Ed25519 over the full purpose+NUL
// and canonical bytes, not an SSHSIG container or an intermediate digest.
func TestExactFrameBoundsAndRawEd25519(t *testing.T) {
	f := newFake(t)
	k, e := New("owner", f.socket, f.public, time.Second)
	if e != nil {
		t.Fatal(e)
	}
	f.set("max-identities")
	if e = k.Check(); e != nil {
		t.Fatal(e)
	}
	f.set("")
	purpose := sign.RecordPurpose
	size := maxPayloadBytes - (1 + 8 + len(publicBlob(f.public)) + len(purpose) + 1 + 4)
	canonical := bytes.Repeat([]byte("x"), size)
	sig, e := k.sign(purpose, canonical)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := base64.StdEncoding.DecodeString(sig.Value)
	if e != nil {
		t.Fatal(e)
	}
	expected := ed25519.Sign(f.private, append(append([]byte(purpose), 0), canonical...))
	if !bytes.Equal(raw, expected) {
		t.Fatal("wire signature differs from raw Ed25519")
	}
	f.mu.Lock()
	before := f.requests
	f.mu.Unlock()
	_, e = k.sign(purpose, append(canonical, 'x'))
	expectCode(t, e, sign.InvalidSignature)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.requests != before {
		t.Fatal("oversized request reached agent")
	}
}

// Possession uses a fresh 32-byte nonce on each call, bound to the exact identity
// and key ID. Even retagging the proof cannot make it verify in any stored-object
// domain; genuine signatures in those domains are the positive controls.
func TestAgentPossessionFreshnessAndDomains(t *testing.T) {
	f := newFake(t)
	k, e := New("agent:proof", f.socket, f.public, time.Second)
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 2; i++ {
		if e := k.ProvePossession(); e != nil {
			t.Fatal(e)
		}
	}
	f.mu.Lock()
	frames := append([][]byte(nil), f.frames...)
	f.mu.Unlock()
	if len(frames) != 2 {
		t.Fatal("proof count", len(frames))
	}
	prefix := []byte("swarma-memory-possession/1\x00")
	suffix := []byte(k.Identity() + k.ID())
	for _, frame := range frames {
		if !bytes.HasPrefix(frame, prefix) || len(frame) != len(prefix)+32+len(suffix) || !bytes.Equal(frame[len(prefix)+32:], suffix) {
			t.Fatal("challenge framing does not bind nonce, identity and key ID")
		}
	}
	if bytes.Equal(frames[0][len(prefix):len(prefix)+32], frames[1][len(prefix):len(prefix)+32]) {
		t.Fatal("nonce reused")
	}
	payload := frames[0][len(prefix):]
	raw := ed25519.Sign(f.private, frames[0])
	proof := sign.Signature{Purpose: sign.PossessionPurpose, Key: k.ID(), Alg: "ed25519", Value: base64.StdEncoding.EncodeToString(raw)}
	v := sign.Ed25519Verifier{}
	if e := v.Verify(sign.PossessionPurpose, payload, proof, f.public); e != nil {
		t.Fatal(e)
	}
	for _, purpose := range []string{sign.RecordPurpose, sign.WritePurpose, sign.PolicyPurpose, sign.RegistrationPurpose, sign.AdvertisementPurpose, sign.DirectoryPurpose} {
		if purpose == sign.PossessionPurpose {
			t.Fatal("shared purpose")
		}
		expectCode(t, v.Verify(purpose, payload, proof, f.public), sign.PurposeMismatch)
		retagged := proof
		retagged.Purpose = purpose
		expectCode(t, v.Verify(purpose, payload, retagged, f.public), sign.InvalidSignature)
		retagged.Value = base64.StdEncoding.EncodeToString(ed25519.Sign(f.private, append(append([]byte(purpose), 0), payload...)))
		if e := v.Verify(purpose, payload, retagged, f.public); e != nil {
			t.Fatal(e)
		}
	}
}

// Public listing alone, malformed proof, refusal and missing-key responses never
// establish possession. Each repaired endpoint accepts a new fresh challenge.
func TestAgentPossessionRefusalAndRetry(t *testing.T) {
	f := newFake(t)
	k, e := New("agent:proof", f.socket, f.public, time.Second)
	if e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		mode string
		code sign.Code
	}{
		{"empty", sign.SignerKeyMissing}, {"sign-failure", sign.SignerRefused},
		{"wrong", sign.InvalidSignature}, {"bad-signature", sign.InvalidSignature},
		{"nonkey", sign.InvalidSignature}, {"non-type", sign.InvalidSignature},
		{"sign-truncated", sign.SignerUnavailable},
	} {
		f.set(tc.mode)
		expectCode(t, k.ProvePossession(), tc.code)
		f.set("")
		if e := k.ProvePossession(); e != nil {
			t.Fatal(tc.mode, e)
		}
	}
}
