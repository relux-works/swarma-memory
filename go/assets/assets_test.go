package memoryassets

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"testing"
	"testing/fstest"
)

func compareCopies(source, embedded fs.FS) error {
	expected := map[string][]byte{}
	for _, pattern := range []string{
		"spec/kernel/schemas/*.json", "spec/kernel/vectors/semantic/*.json",
		"spec/domains/decisions/assumption.json", "spec/domains/decisions/decision.json",
		"spec/domains/decisions/decision_proposal.json", "spec/domains/decisions/rule.json", "spec/domains/profiles-synthetic/*.json",
	} {
		names, err := fs.Glob(source, pattern)
		if err != nil || len(names) == 0 {
			return fmt.Errorf("missing source group %s: %v", pattern, err)
		}
		for _, name := range names {
			data, err := fs.ReadFile(source, name)
			if err != nil {
				return err
			}
			expected[name] = data
		}
	}
	for _, name := range []string{"passing.txt", "passing-ops.txt"} {
		data, err := fs.ReadFile(source, "go/conformance/"+name)
		if err != nil {
			return err
		}
		expected["conformance/"+name] = data
	}
	err := fs.WalkDir(embedded, ".", func(name string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		data, err := fs.ReadFile(embedded, name)
		if err != nil {
			return err
		}
		want, ok := expected[name]
		if !ok {
			return fmt.Errorf("unexpected embedded file %s", name)
		}
		if !bytes.Equal(want, data) {
			return fmt.Errorf("embedded bytes differ: %s", name)
		}
		delete(expected, name)
		return nil
	})
	if err != nil {
		return err
	}
	if len(expected) != 0 {
		return fmt.Errorf("missing embedded files: %d", len(expected))
	}
	return nil
}

// The shipped schemas, domains, semantic vectors and ratchets have exactly the
// same file set and bytes as their source inputs; this does not validate semantics.
func TestEmbeddedAssetsMatchSource(t *testing.T) {
	if err := compareCopies(os.DirFS("../.."), Files); err != nil {
		t.Fatal(err)
	}
}

// Bounded checker controls require the intended byte/set rejection with a nearby
// valid fixture. Source drift is checked against the embedded bytes directly.
func TestEmbeddedAssetControls(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		mutate     func(fstest.MapFS, fstest.MapFS)
	}{
		{"valid", "", func(_, _ fstest.MapFS) {}},
		{"changed copy", "embedded bytes differ:", func(_, copy fstest.MapFS) { copy["spec/kernel/schemas/control.json"].Data = []byte("changed") }},
		{"changed source", "embedded bytes differ:", func(source, _ fstest.MapFS) { source["spec/kernel/schemas/control.json"].Data = []byte("new source") }},
		{"missing copy", "missing embedded files:", func(_, copy fstest.MapFS) { delete(copy, "spec/kernel/schemas/control.json") }},
		{"extra copy", "unexpected embedded file", func(_, copy fstest.MapFS) {
			copy["spec/kernel/schemas/extra.json"] = &fstest.MapFile{Data: []byte("extra")}
		}},
		{"unused fixture copy", "unexpected embedded file spec/domains/decisions/fixture.json", func(_, copy fstest.MapFS) {
			copy["spec/domains/decisions/fixture.json"] = &fstest.MapFile{Data: []byte("invalid")}
		}},
		{"missing source", "missing source group", func(source, _ fstest.MapFS) { delete(source, "spec/kernel/schemas/control.json") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source, copy := fstest.MapFS{}, fstest.MapFS{}
			for _, name := range []string{"spec/kernel/schemas/control.json", "spec/kernel/vectors/semantic/control.json",
				"spec/domains/decisions/assumption.json", "spec/domains/decisions/decision.json",
				"spec/domains/decisions/decision_proposal.json", "spec/domains/decisions/rule.json",
				"spec/domains/profiles-synthetic/control.json"} {
				source[name] = &fstest.MapFile{Data: []byte("source")}
				copy[name] = &fstest.MapFile{Data: []byte("source")}
			}
			// Unused domain fixtures, even invalid JSON, are outside the runtime set.
			source["spec/domains/decisions/fixture.json"] = &fstest.MapFile{Data: []byte("invalid")}

			for _, name := range []string{"passing.txt", "passing-ops.txt"} {
				source["go/conformance/"+name] = &fstest.MapFile{Data: []byte("ratchet")}
				copy["conformance/"+name] = &fstest.MapFile{Data: []byte("ratchet")}
			}
			tc.mutate(source, copy)
			err := compareCopies(source, copy)
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}
