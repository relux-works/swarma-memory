package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// The exact encoded key boundary round-trips for ASCII, escaped and UTF-8
// identities. One extra encoded byte refuses before publication and permits retry.
func TestKeyInitEncodedLimit(t *testing.T) {
	for name, tail := range map[string]string{
		"ascii":     strings.Repeat("x", 4004),
		"quote":     strings.Repeat("\"", 2002),
		"html":      strings.Repeat("<", 667) + "xx",
		"utf8":      strings.Repeat("界", 1334) + "xx",
		"emoji":     strings.Repeat("🙂", 1001),
		"separator": strings.Repeat("\u2028", 667) + "xx",
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			h := &cliHarness{t: t, root: root, env: cleanEnv(root)}
			valid := filepath.Join(root, "valid")
			identity := "person:" + tail
			h.invoke(valid, 0, "keys", "init", "--identity", identity)
			m, _ := h.invoke(valid, 0, "keys", "show")
			if m["data"].(map[string]any)["identity"] != identity {
				t.Fatal("identity changed on load")
			}
			info, err := os.Stat(filepath.Join(valid, "localkey.json"))
			if err != nil || info.Size() != 4096 || info.Mode().Perm() != 0600 {
				t.Fatal("exact key boundary/mode", info, err)
			}
			for i, rejected := range []string{identity + "x", "person:" + strings.Repeat("x", 5000)} {
				home := filepath.Join(root, string(rune('a'+i)))
				m, _ := h.invoke(home, 3, "keys", "init", "--identity", rejected)
				if errorCodeOf(m) != "invalid_key" {
					t.Fatal(m)
				}
				for _, name := range []string{"config.json", "localkey.json"} {
					if _, err := os.Lstat(filepath.Join(home, name)); !os.IsNotExist(err) {
						t.Fatal("rejected init published state", name, err)
					}
				}
				h.invoke(home, 0, "keys", "init", "--identity", "person:retry")
				h.invoke(home, 0, "keys", "show")
			}
		})
	}
}

// Config save must obey the loader's exact encoded bound, preserving the last
// loadable config on oversized/invalid input, including escaping and UTF-8.
func TestConfigSaveLoadContract(t *testing.T) {
	configSaveLoadContract(t, t.TempDir())
}

// A home reached through a symlinked parent stores canonical paths at exactly
// 1 MiB; one extra encoded byte refuses without replacing the loadable config.
func TestConfigSaveLoadSymlinkedParent(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "longer-canonical-parent")
	if err := os.MkdirAll(filepath.Join(parent, "home"), 0700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(parent, alias); err != nil {
		t.Fatal(err)
	}
	configSaveLoadContract(t, filepath.Join(alias, "home"))
}

func configSaveLoadContract(t *testing.T, dir string) {
	t.Helper()
	want, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	h, err := resolveHome(dir)
	if err != nil || h.config != want || h.state != want {
		t.Fatal("home did not resolve to its canonical directory", h, want, err)
	}
	clone, cache := h.paths("space:test")
	c := localConfig{"person:test", h.keyfile(), []localSpace{{"", "space:test", "remote:", "main", clone, cache, strings.Repeat("a", 64), "project"}}}
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	c.Spaces[0].Remote += strings.Repeat("x", (1<<20)-len(b)-1)
	if err := h.save(c); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(h.filename())
	if err != nil || len(before) != 1<<20 {
		t.Fatal("exact config boundary", len(before), err)
	}
	if got, err := h.load(); err != nil || !reflect.DeepEqual(got, c) {
		t.Fatal("canonical config did not round-trip", err)
	}
	for i, mutate := range []func(*localConfig){
		func(c *localConfig) { c.Spaces[0].Remote += "x" },
		func(c *localConfig) { c.Spaces[0].Remote += "<" },
		func(c *localConfig) { c.Spaces[0].Remote += "界" },
		func(c *localConfig) { c.Spaces[0].ID = "" },
		func(c *localConfig) { c.Spaces = nil },
		func(c *localConfig) { c.Spaces[0].Remote = "remote:"; c.Spaces[0].ClonePath += "/outside" },
		func(c *localConfig) { c.Spaces[0].Remote = "remote:"; c.KeyFile += "/outside" },
		func(c *localConfig) { c.Spaces[0].Remote = string([]byte{0xff}) },
		func(c *localConfig) { c.Spaces[0].ID = string([]byte{0xff}) },
		func(c *localConfig) { c.Spaces[0].Branch = string([]byte{0xff}) },
	} {
		next := c
		next.Spaces = append([]localSpace{}, c.Spaces...)
		mutate(&next)
		if i == 0 {
			encoded, err := json.Marshal(next)
			if err != nil || len(encoded)+1 != (1<<20)+1 {
				t.Fatal("negative control is not exactly one encoded byte over", len(encoded)+1, err)
			}
		}
		if err := h.save(next); err == nil || classify(err) != (wireError{"invalid_configuration", 3}) {
			t.Fatal("invalid config save", err)
		}
		after, err := os.ReadFile(h.filename())
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("invalid save replaced good config", err)
		}
		if _, err := h.load(); err != nil {
			t.Fatal("failed save left unusable config", err)
		}
	}
}

// An add/init that would exceed the config bound must refuse before cloning or
// publishing genesis. Existing state stays readable and a smaller valid retry works.
func TestSpaceConfigPreflight(t *testing.T) {
	h := newCLI(t)
	c := h.config(h.owner)
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	c.Spaces[0].Remote += strings.Repeat("x", (1<<20)-len(b)-1)
	before, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	before = append(before, '\n')
	configPath := filepath.Join(h.owner, "config.json")
	if err := os.WriteFile(configPath, before, 0600); err != nil {
		t.Fatal(err)
	}
	h.invoke(h.owner, 0, "spaces", "list")
	remote := filepath.Join(h.root, "empty.git")
	h.git(h.root, "init", "--bare", "--initial-branch=main", remote)
	for _, command := range []string{"add", "init"} {
		args := []string{"spaces", command, "space:second", "--remote", remote}
		if command == "add" {
			args = append(args, "--genesis", h.pin)
		}
		m, _ := h.invoke(h.owner, 3, args...)
		if errorCodeOf(m) != "invalid_configuration" {
			t.Fatal(m)
		}
		after, err := os.ReadFile(configPath)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("refusal changed existing config", err)
		}
		clone, cache := (home{h.owner, h.owner}).paths("space:second")
		for _, path := range []string{clone, cache} {
			if _, err := os.Lstat(path); !os.IsNotExist(err) {
				t.Fatal("refusal created local space state", path, err)
			}
		}
		if refs := h.git(remote, "for-each-ref", "--format=%(refname)"); refs != "" {
			t.Fatal("refusal published a remote policy")
		}
		h.invoke(h.owner, 0, "spaces", "list")
	}
	c.Spaces[0].Remote = h.remote
	small, _ := json.Marshal(c)
	if err := os.WriteFile(configPath, small, 0600); err != nil {
		t.Fatal(err)
	}
	h.invoke(h.owner, 0, "spaces", "init", "space:second", "--remote", remote)
	h.invoke(h.owner, 0, "spaces", "show", "space:second")
}
