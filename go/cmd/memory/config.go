package main

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"unicode/utf8"

	"github.com/relux-works/swarma-memory/go/kernel"
	"github.com/relux-works/swarma-memory/go/sign/localkey"
)

type localConfig struct {
	Identity string       `json:"identity"`
	KeyFile  string       `json:"key_file"`
	Spaces   []localSpace `json:"spaces"`
}
type localSpace struct {
	DirectorySpace string `json:"directory_space,omitempty"`
	ID             string `json:"id"`
	Remote         string `json:"remote"`
	Branch         string `json:"branch"`
	ClonePath      string `json:"clone_path"`
	CachePath      string `json:"cache_path"`
	GenesisDigest  string `json:"genesis_digest"`
	Kind           string `json:"kind"`
}
type home struct{ config, state string }

const maxConfigBytes = 1 << 20

//go:embed config.schema.json
var configSchema embed.FS

func resolveHome(override string) (home, error) {
	config, state := override, override
	if config == "" {
		config = os.Getenv("MEMORY_HOME")
		state = config
	}
	if config == "" {
		config = os.Getenv("XDG_CONFIG_HOME")
		if config == "" {
			config = filepath.Join(os.Getenv("HOME"), ".config")
		}
		config = filepath.Join(config, "swarma-memory")
		state = os.Getenv("XDG_STATE_HOME")
		if state == "" {
			state = filepath.Join(os.Getenv("HOME"), ".local", "state")
		}
		state = filepath.Join(state, "swarma-memory")
	}
	c, e := canonicalPath(config)
	if e != nil {
		return home{}, e
	}
	s, e := canonicalPath(state)
	if e != nil {
		return home{}, e
	}
	for _, dir := range []string{c, s} {
		if repositoryAncestor(dir) {
			return home{}, cliError{"home_inside_repository", 3}
		}
	}
	return home{c, s}, nil
}
func repositoryAncestor(dir string) bool {
	for p := dir; ; p = filepath.Dir(p) {
		if _, e := os.Lstat(filepath.Join(p, ".git")); e == nil {
			return true
		}
		// Bare repositories and Git metadata directories have no .git child.
		if head, e := os.Stat(filepath.Join(p, "HEAD")); e == nil && head.Mode().IsRegular() {
			objects, oe := os.Stat(filepath.Join(p, "objects"))
			refs, re := os.Stat(filepath.Join(p, "refs"))
			if oe == nil && re == nil && objects.IsDir() && refs.IsDir() {
				return true
			}
		}
		if filepath.Dir(p) == p {
			return false
		}
	}
}
func canonicalPath(path string) (string, error) {
	path, e := filepath.Abs(path)
	if e != nil {
		return "", cliError{"invalid_configuration", 3}
	}
	parent := path
	tail := []string{}
	for {
		resolved, e := filepath.EvalSymlinks(parent)
		if e == nil {
			for i := len(tail) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, tail[i])
			}
			return resolved, nil
		}
		if !errors.Is(e, os.ErrNotExist) {
			return "", cliError{"config_io", 6}
		}
		tail = append(tail, filepath.Base(parent))
		next := filepath.Dir(parent)
		if next == parent {
			return "", cliError{"config_io", 6}
		}
		parent = next
	}
}
func (h home) filename() string { return filepath.Join(h.config, "config.json") }
func (h home) keyfile() string  { return filepath.Join(h.config, "localkey.json") }
func (h home) paths(id string) (string, string) {
	d := sha256.Sum256([]byte(id))
	name := hex.EncodeToString(d[:])
	return filepath.Join(h.state, "clones", name), filepath.Join(h.state, "caches", name)
}

func (h home) load() (localConfig, error) {
	var c localConfig
	info, e := os.Lstat(h.filename())
	if errors.Is(e, os.ErrNotExist) {
		return c, cliError{"missing_config", 2}
	}
	if e != nil {
		return c, cliError{"config_io", 6}
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > maxConfigBytes {
		return c, cliError{"invalid_configuration", 3}
	}
	b, e := os.ReadFile(h.filename())
	if e != nil {
		return c, cliError{"config_io", 6}
	}
	return h.decodeConfig(b)
}

func (h home) decodeConfig(b []byte) (localConfig, error) {
	var c localConfig
	if len(b) > maxConfigBytes {
		return c, cliError{"invalid_configuration", 3}
	}
	value, f := kernel.DecodeJSON(b)
	if f != nil {
		return c, cliError{"invalid_configuration", 3}
	}
	schemas, f := kernel.LoadSchemas(configSchema)
	if f != nil {
		return c, cliError{"internal", 6}
	}
	if f = schemas.Validate(value, "urn:bounded-evidence:cli:1:config"); f != nil {
		return c, cliError{"invalid_configuration", 3}
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e := d.Decode(&c); e != nil {
		return c, cliError{"invalid_configuration", 3}
	}
	if c.Identity == "" || c.KeyFile != h.keyfile() || c.Spaces == nil {
		return c, cliError{"invalid_configuration", 3}
	}
	seen := map[string]bool{}
	for _, s := range c.Spaces {
		clone, cache := h.paths(s.ID)
		if s.ID == "" || seen[s.ID] || s.Remote == "" || s.Branch == "" || s.GenesisDigest == "" || s.ClonePath != clone || s.CachePath != cache || s.Kind != "agent" && s.Kind != "project" && s.Kind != "platform" {
			return c, cliError{"invalid_configuration", 3}
		}
		for _, p := range []string{clone, cache} {
			resolved, e := canonicalPath(p)
			if e != nil || resolved != p {
				return c, cliError{"invalid_configuration", 3}
			}
		}
		seen[s.ID] = true
		if repositoryAncestor(filepath.Dir(clone)) || repositoryAncestor(cache) {
			return c, cliError{"home_inside_repository", 3}
		}
	}
	sort.Slice(c.Spaces, func(i, j int) bool { return c.Spaces[i].ID < c.Spaces[j].ID })
	return c, nil
}
func privateDir(path string) error {
	if e := os.MkdirAll(path, 0700); e != nil {
		return cliError{"config_io", 6}
	}
	if e := os.Chmod(path, 0700); e != nil {
		return cliError{"config_io", 6}
	}
	return nil
}
func (h home) save(c localConfig) error {
	b, e := h.encodeConfig(c)
	if e != nil {
		return e
	}
	if e := privateDir(h.config); e != nil {
		return e
	}
	f, e := os.CreateTemp(h.config, ".config-*")
	if e != nil {
		return cliError{"config_io", 6}
	}
	defer os.Remove(f.Name())
	if _, e = f.Write(b); e == nil {
		e = f.Sync()
	}
	closeError := f.Close()
	if e == nil {
		e = closeError
	}
	if e == nil {
		e = os.Rename(f.Name(), h.filename())
	}
	if e != nil {
		return cliError{"config_io", 6}
	}
	return nil
}

// Preflight uses the same bounded decoder as load, before publishing local or
// remote state. Reject invalid UTF-8 instead of json.Marshal's lossy replacement.
func (h home) encodeConfig(c localConfig) ([]byte, error) {
	texts := []string{c.Identity, c.KeyFile}
	for _, s := range c.Spaces {
		texts = append(texts, s.ID, s.Remote, s.Branch, s.ClonePath, s.CachePath, s.GenesisDigest, s.Kind, s.DirectorySpace)
	}
	for _, s := range texts {
		if !utf8.ValidString(s) {
			return nil, cliError{"invalid_configuration", 3}
		}
	}
	if c.Spaces != nil {
		c.Spaces = append([]localSpace{}, c.Spaces...)
	}
	sort.Slice(c.Spaces, func(i, j int) bool { return c.Spaces[i].ID < c.Spaces[j].ID })
	b, e := json.Marshal(c)
	if e != nil {
		return nil, cliError{"internal", 6}
	}
	b = append(b, '\n')
	if _, e := h.decodeConfig(b); e != nil {
		return nil, e
	}
	return b, nil
}
func (h home) key(c localConfig) (*localkey.Key, error) {
	k, e := localkey.Load(os.DirFS(h.config), "localkey.json")
	if e != nil {
		return nil, e
	}
	if k.Identity() != c.Identity {
		return nil, cliError{"identity_mismatch", 3}
	}
	return k, nil
}
