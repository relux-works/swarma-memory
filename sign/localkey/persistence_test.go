package localkey

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/relux-works/swarma-memory/sign"
)

// Save rejects an oversized in-memory key before creating/truncating any file;
// Load also rejects compact hand-edited encodings that cannot be saved within
// the canonical bound. The exact-boundary key still round-trips unchanged.
func TestEncodedKeyPersistenceContract(t *testing.T) {
	k, err := Generate("person:" + strings.Repeat("x", 4004))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	filename := filepath.Join(dir, "key.json")
	if err := k.Save(filename); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filename)
	if err != nil || info.Size() != 4096 {
		t.Fatal("exact boundary", info, err)
	}
	loaded, err := Load(os.DirFS(dir), "key.json")
	if err != nil || loaded.ID() != k.ID() || loaded.Identity() != k.Identity() {
		t.Fatal("boundary round trip", err)
	}
	k.identity += "x"
	missing := filepath.Join(dir, "missing.json")
	var d *sign.Diagnostic
	if err := k.Save(missing); !errors.As(err, &d) || d.Code != sign.InvalidKey {
		t.Fatal("oversized save", err)
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatal("oversized save created file", err)
	}
	sentinel := filepath.Join(dir, "sentinel")
	if err := os.WriteFile(sentinel, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := k.Save(sentinel); !errors.As(err, &d) || d.Code != sign.InvalidKey {
		t.Fatal("oversized overwrite", err)
	}
	if data, err := os.ReadFile(sentinel); err != nil || !bytes.Equal(data, []byte("preserve")) {
		t.Fatal("oversized save changed existing file", err)
	}
	compact := []byte(`{"identity":"` + strings.Repeat("<", 700) + `","alg":"ed25519","seed":"` + base64.StdEncoding.EncodeToString(make([]byte, 32)) + `"}`)
	_, err = Load(fstest.MapFS{"key.json": &fstest.MapFile{Data: compact, Mode: 0600}}, "key.json")
	if !errors.As(err, &d) || d.Code != sign.InvalidKey {
		t.Fatal("load accepted unpersistable canonical encoding", err)
	}
}
