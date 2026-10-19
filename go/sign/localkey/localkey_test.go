package localkey_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/relux-works/swarma-memory/go/sign"
	"github.com/relux-works/swarma-memory/go/sign/localkey"
)

func check(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func code(t *testing.T, err error, want sign.Code) {
	t.Helper()
	var d *sign.Diagnostic
	if !errors.As(err, &d) || d.Code != want {
		t.Fatalf("got %v; want %s", err, want)
	}
}

// TestEphemeralKeyPersistence proves generated per-identity keys round trip via
// a new 0600 file, stable raw-public-key SHA-256 IDs, and exclusive save semantics.
// Existing key files, symlinks and unrelated targets remain byte-for-byte intact.
func TestEphemeralKeyPersistence(t *testing.T) {
	k, e := localkey.Generate("principal:synthetic")
	check(t, e)
	other, e := localkey.Generate(k.Identity())
	check(t, e)
	if k.ID() == other.ID() {
		t.Fatal("independent keys identical")
	}
	digest := sha256.Sum256(k.PublicKey())
	if k.ID() != "ed25519:sha256:"+hex.EncodeToString(digest[:]) {
		t.Fatal("key id framing changed")
	}
	dir := t.TempDir()
	filename := filepath.Join(dir, "ephemeral.json")
	check(t, k.Save(filename))
	info, e := os.Stat(filename)
	check(t, e)
	if info.Mode().Perm() != 0600 {
		t.Fatal("private mode not 0600")
	}
	loaded, e := localkey.Load(os.DirFS(dir), "ephemeral.json")
	check(t, e)
	if loaded.Identity() != k.Identity() || loaded.ID() != k.ID() || !bytes.Equal(loaded.PublicKey(), k.PublicKey()) {
		t.Fatal("key round trip changed public identity")
	}
	before, e := os.ReadFile(filename)
	check(t, e)
	code(t, other.Save(filename), sign.KeyIO)
	after, e := os.ReadFile(filename)
	check(t, e)
	if !bytes.Equal(before, after) {
		t.Fatal("existing key overwritten")
	}
	link := filepath.Join(dir, "link.json")
	check(t, os.Symlink(filename, link))
	code(t, other.Save(link), sign.KeyIO)
	_, e = localkey.Load(os.DirFS(dir), "link.json")
	code(t, e, sign.KeyPermissions)
	after, e = os.ReadFile(filename)
	check(t, e)
	if !bytes.Equal(before, after) {
		t.Fatal("symlink target overwritten")
	}
	// Ensure normal diagnostic formatting cannot disclose private seed material.
	var doc map[string]string
	check(t, json.Unmarshal(before, &doc))
	seed := doc["seed"]
	for _, printed := range []string{fmt.Sprint(k), fmt.Sprintf("%#v", k), fmt.Sprintf("%+v", k), fmt.Sprint(*k), fmt.Sprintf("%#v", *k)} {
		if strings.Contains(printed, seed) {
			t.Fatal("key formatting exposed private seed")
		}
	}
	check(t, os.Chmod(filename, 0644))
	_, e = localkey.Load(os.DirFS(dir), "ephemeral.json")
	code(t, e, sign.KeyPermissions)
	check(t, os.Chmod(filename, 0600))
	_, e = localkey.Load(os.DirFS(dir), "ephemeral.json")
	check(t, e)
}

// TestKeyLoadRefusals proves malformed, oversized, unsafe-mode and unknown-field
// key files have typed non-secret diagnostics; generated keys are the control.
func TestKeyLoadRefusals(t *testing.T) {
	k, e := localkey.Generate("principal:synthetic")
	check(t, e)
	dir := t.TempDir()
	check(t, k.Save(filepath.Join(dir, "key.json")))
	valid, e := os.ReadFile(filepath.Join(dir, "key.json"))
	check(t, e)
	for _, tc := range []struct {
		name string
		data []byte
		mode os.FileMode
		want sign.Code
	}{
		{"valid", valid, 0600, ""},
		{"open mode", valid, 0644, sign.KeyPermissions},
		{"read-only mode", valid, 0400, sign.KeyPermissions},
		{"empty", nil, 0600, sign.InvalidKey},
		{"oversized", bytes.Repeat([]byte("a"), 4097), 0600, sign.InvalidKey},
		{"bad json", []byte(`{"seed":"private-synthetic-marker"`), 0600, sign.InvalidKey},
		{"duplicate", []byte(`{"identity":"a","identity":"b","alg":"ed25519","seed":"x"}`), 0600, sign.InvalidKey},
		{"wrong algorithm", []byte(`{"identity":"a","alg":"other","seed":"x"}`), 0600, sign.InvalidKey},
		{"unknown field", append(append([]byte{}, bytes.TrimSuffix(valid, []byte("}"))...), []byte(`,"extra":true}`)...), 0600, sign.InvalidKey},
		{"bad seed", []byte(`{"identity":"a","alg":"ed25519","seed":"private-synthetic-marker"}`), 0600, sign.InvalidKey},
		{"empty identity", []byte(`{"identity":"","alg":"ed25519","seed":"` + base64.StdEncoding.EncodeToString(make([]byte, 32)) + `"}`), 0600, sign.InvalidKey},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := fstest.MapFS{"key.json": &fstest.MapFile{Data: tc.data, Mode: tc.mode}}
			_, err := localkey.Load(source, "key.json")
			if tc.want == "" {
				check(t, err)
			} else {
				code(t, err, tc.want)
				if strings.Contains(err.Error(), "private-synthetic-marker") {
					t.Fatal("diagnostic leaked rejected key")
				}
			}
		})
	}
	_, e = localkey.Load(os.DirFS(dir), "../key.json")
	code(t, e, sign.KeyIO)
	_, e = localkey.Load(nil, "key.json")
	code(t, e, sign.KeyIO)
	_, e = localkey.Generate("")
	code(t, e, sign.InvalidKey)
	var nilKey *localkey.Key
	code(t, nilKey.Save(filepath.Join(dir, "nil.json")), sign.InvalidKey)
}
