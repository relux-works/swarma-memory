package space

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"sort"
	"strconv"
	"strings"
)

// writeTree computes the complete proposed Git tree without writing objects,
// an index or working files. Existing modes are preserved; new records are 0644.
// Binding the parent alone would permit transplanting a signature into another
// commit at the same parent alongside independently signed files.
func (r *Repository) writeTree(ctx context.Context, parent string, files map[string][]byte) (string, error) {
	entries, e := r.listTree(ctx, parent, true)
	if e != nil {
		return "", e
	}
	for path, data := range files {
		if _, exists := entries[path]; exists {
			return "", fail("version_conflict")
		}
		entries[path] = treeEntry{"100644", gitObjectID("blob", data, len(parent))}
	}
	return treeObjectID(entries, len(parent))
}

func gitObjectID(kind string, data []byte, width int) string {
	var h hash.Hash = sha1.New()
	if width == 64 {
		h = sha256.New()
	}
	_, _ = h.Write([]byte(kind + " " + strconv.Itoa(len(data)) + "\x00"))
	_, _ = h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

func treeObjectID(entries map[string]treeEntry, width int) (string, error) {
	files := map[string]treeEntry{}
	dirs := map[string]map[string]treeEntry{}
	for path, entry := range entries {
		entry.mode = strings.TrimLeft(entry.mode, "0")
		name, rest, nested := strings.Cut(path, "/")
		if name == "" || name == "." || name == ".." || strings.ContainsRune(name, 0) {
			return "", fail("invalid_path")
		}
		if nested {
			if dirs[name] == nil {
				dirs[name] = map[string]treeEntry{}
			}
			dirs[name][rest] = entry
		} else {
			files[name] = entry
		}
	}
	for name, children := range dirs {
		if existing, exists := files[name]; exists && existing.mode != "040000" && existing.mode != "40000" {
			return "", fail("invalid_path")
		}
		oid, e := treeObjectID(children, width)
		if e != nil {
			return "", e
		}
		files[name] = treeEntry{"40000", oid}
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	// Git compares directory names with a trailing slash, not a NUL.
	key := func(name string) string {
		if files[name].mode == "40000" {
			return name + "/"
		}
		return name
	}
	sort.Slice(names, func(i, j int) bool { return key(names[i]) < key(names[j]) })
	var body bytes.Buffer
	for _, name := range names {
		entry := files[name]
		oid, e := hex.DecodeString(entry.blob)
		if e != nil || len(entry.blob) != width {
			return "", fail("invalid_history")
		}
		body.WriteString(strings.TrimLeft(entry.mode, "0") + " " + name)
		body.WriteByte(0)
		body.Write(oid)
	}
	return gitObjectID("tree", body.Bytes(), width), nil
}
