// Package localkey is the temporary per-identity Ed25519 signer. It has no
// connection to host SSH keys, agents, registries or external key holders.
package localkey

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"path"
	"unicode/utf8"

	"github.com/relux-works/swarma-memory/kernel"
	"github.com/relux-works/swarma-memory/sign"
	"github.com/relux-works/swarma-memory/space"
)

type Key struct {
	identity string
	private  ed25519.PrivateKey
}

// Generation, persistence and loading share the encoded-file bound, including
// JSON escaping and UTF-8 bytes in the identity.
const maxEncodedKeyBytes = 4096

var _ sign.Signer = (*Key)(nil)
var _ sign.WriteSigner = (*Key)(nil)
var _ space.PolicySigner = (*Key)(nil)

func Generate(identity string) (*Key, error) {
	if identity == "" || !utf8.ValidString(identity) {
		return nil, sign.Fail(sign.InvalidKey, "identity")
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, sign.Fail(sign.InvalidKey, "generate")
	}
	k := &Key{identity, private}
	if _, err := k.encode(); err != nil {
		return nil, err
	}
	return k, nil
}
func (k Key) String() string   { return "localkey.Key(<redacted>)" }
func (k Key) GoString() string { return k.String() }
func (k *Key) Identity() string {
	if k == nil {
		return ""
	}
	return k.identity
}
func (k *Key) PublicKey() []byte {
	if k == nil || len(k.private) != ed25519.PrivateKeySize {
		return nil
	}
	return append([]byte(nil), k.private[32:]...)
}
func (k *Key) ID() string { return sign.KeyID(k.PublicKey()) }
func (k *Key) Sign(record sign.CanonicalRecord) (sign.Signature, error) {
	if record.Submitter() == "" {
		return sign.Signature{}, sign.Fail(sign.InvalidRecord, "record")
	}
	if record.Submitter() != k.Identity() {
		return sign.Signature{}, sign.Fail(sign.SubmitterMismatch, "record.envelope.submitter")
	}
	return k.sign(sign.RecordPurpose, record.Bytes())
}
func (k *Key) SignPolicy(p space.CanonicalPolicy) (sign.Signature, error) {
	if p.Author() == "" {
		return sign.Signature{}, sign.Fail(sign.InvalidPolicy, "policy")
	}
	if p.Author() != k.Identity() {
		return sign.Signature{}, sign.Fail(sign.SubmitterMismatch, "policy.author")
	}
	return k.sign(sign.PolicyPurpose, p.Bytes())
}
func (k *Key) SignRegistration(r space.CanonicalRegistration) (sign.Signature, error) {
	if r.Author() == "" {
		return sign.Signature{}, sign.Fail(sign.InvalidRegistration, "registration")
	}
	if r.Author() != k.Identity() {
		return sign.Signature{}, sign.Fail(sign.SubmitterMismatch, "registration.author")
	}
	return k.sign(sign.RegistrationPurpose, r.Bytes())
}
func (k *Key) sign(purpose string, canonical []byte) (sign.Signature, error) {
	if k == nil || len(k.private) != ed25519.PrivateKeySize {
		return sign.Signature{}, sign.Fail(sign.InvalidKey, "key")
	}
	raw := ed25519.Sign(k.private, sign.Frame(purpose, canonical))
	return sign.Signature{Purpose: purpose, Key: k.ID(), Alg: "ed25519", Value: base64.StdEncoding.EncodeToString(raw)}, nil
}

// Save creates a new regular 0600 file exclusively. It never truncates an
// existing file or symlink. Callers provide a private trusted parent directory.
func (k *Key) Save(filename string) error {
	data, err := k.encode()
	if err != nil {
		return err
	}
	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return sign.Fail(sign.KeyIO, "save")
	}
	defer f.Close()
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(filename)
		return sign.Fail(sign.KeyIO, "save")
	}
	return nil
}

func (k *Key) encode() ([]byte, error) {
	if k == nil || len(k.private) != ed25519.PrivateKeySize || k.identity == "" || !utf8.ValidString(k.identity) {
		return nil, sign.Fail(sign.InvalidKey, "key")
	}
	data, err := json.Marshal(map[string]string{"identity": k.identity, "alg": "ed25519", "seed": base64.StdEncoding.EncodeToString(k.private.Seed())})
	if err != nil || len(data) > maxEncodedKeyBytes {
		return nil, sign.Fail(sign.InvalidKey, "key")
	}
	return data, nil
}

// Load accepts an adapter-owned filesystem of ephemeral key files. Parent
// directories and filesystem behavior must be trusted; no ambient key discovery.
func Load(source fs.FS, name string) (*Key, error) {
	if source == nil || !fs.ValidPath(name) {
		return nil, sign.Fail(sign.KeyIO, "load")
	}
	entries, err := fs.ReadDir(source, path.Dir(name))
	if err != nil {
		return nil, sign.Fail(sign.KeyIO, "load")
	}
	regular := false
	for _, e := range entries {
		if e.Name() == path.Base(name) {
			regular = e.Type().IsRegular()
		}
	}
	if !regular {
		return nil, sign.Fail(sign.KeyPermissions, "key")
	}
	f, err := source.Open(name)
	if err != nil {
		return nil, sign.Fail(sign.KeyIO, "load")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, sign.Fail(sign.KeyIO, "load")
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Mode()&(fs.ModeSetuid|fs.ModeSetgid|fs.ModeSticky) != 0 {
		return nil, sign.Fail(sign.KeyPermissions, "key")
	}
	if info.Size() < 1 || info.Size() > maxEncodedKeyBytes {
		return nil, sign.Fail(sign.InvalidKey, "key")
	}
	// Bounded read even if a filesystem reports an inaccurate size.
	data, err := io.ReadAll(io.LimitReader(f, maxEncodedKeyBytes+1))
	if err != nil {
		return nil, sign.Fail(sign.KeyIO, "load")
	}
	if len(data) > maxEncodedKeyBytes {
		return nil, sign.Fail(sign.InvalidKey, "key")
	}

	value, r := kernel.DecodeJSON(data)
	if r != nil {
		return nil, sign.Fail(sign.InvalidKey, "key")
	}
	m, ok := value.(map[string]any)
	if !ok || len(m) != 3 || m["alg"] != "ed25519" {
		return nil, sign.Fail(sign.InvalidKey, "key")
	}
	identity, ok := m["identity"].(string)
	seed, seedOK := m["seed"].(string)
	if !ok || identity == "" || !seedOK {
		return nil, sign.Fail(sign.InvalidKey, "key")
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(seed)
	if err != nil || len(raw) != ed25519.SeedSize || base64.StdEncoding.EncodeToString(raw) != seed {
		return nil, sign.Fail(sign.InvalidKey, "key")
	}
	k := &Key{identity, ed25519.NewKeyFromSeed(raw)}
	if _, err := k.encode(); err != nil {
		return nil, err
	}
	return k, nil
}

// SignWrite signs the complete validated transaction only for its authenticated actor.
func (k *Key) SignWrite(write sign.CanonicalWrite) (sign.Signature, error) {
	if k == nil || write.Actor() != k.identity || len(write.Bytes()) == 0 {
		return sign.Signature{}, sign.Fail(sign.SubmitterMismatch, "write.operation.context.actor")
	}
	return k.sign(sign.WritePurpose, write.Bytes())
}
