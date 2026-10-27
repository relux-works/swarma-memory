package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/relux-works/swarma-memory/go/agentprofile"
	"github.com/relux-works/swarma-memory/go/kernel"
)

// A full Matrix room/event locator and benign multiline excerpt survive signed
// CLI intake and independent-reader replay with zero diagnostics. UUID metadata
// remains accepted; the source is documentary and unavailable, not live-resolved.
func TestWriteMatrixSessionLocator(t *testing.T) {
	h := newCLI(t)
	h.connectReader()
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
	room := "!" + alphabet[:43] + ":example.invalid:8448"
	event := "$" + alphabet[:43]
	excerpt := "Synthetic attributed observation\nwith its exact final newline.\n"
	m, _, _ := h.input(h.owner, excerpt, 0, "add", "assertion", "--id", "record:matrix", "--content", "An attributed observation", "--idempotency-key", "12345678-9abc-def0-1234-56789abcdef0", "--source-session", "matrix:"+room+":"+event, "--source-text", "-")
	if len(agentprofile.Array(agentprofile.Object(agentprofile.Object(m["data"])["receipt"])["refs"])) != 3 {
		t.Fatal("source transaction was not atomic")
	}
	synced, _ := h.invoke(h.reader, 0, "sync", "--space", "space:test")
	syncSpaces := agentprofile.Array(agentprofile.Object(synced["data"])["spaces"])
	if len(syncSpaces) != 1 || agentprofile.Object(syncSpaces[0])["diagnostic_count"] != int64(0) || len(agentprofile.Array(agentprofile.Object(syncSpaces[0])["diagnostics"])) != 0 {
		t.Fatal("reader sync diagnostics", synced)
	}
	for _, command := range []string{"recall", "explain"} {
		target := "*"
		if command == "explain" {
			target = "record:matrix"
		}
		result, _ := h.invoke(h.reader, 0, command, target, "--space", "space:test")
		spaces := agentprofile.Array(agentprofile.Object(result["data"])["spaces"])
		if len(spaces) != 1 {
			t.Fatal("wrong read spaces")
		}
		space := agentprofile.Object(spaces[0])
		if len(agentprofile.Array(space["diagnostics"])) != 0 {
			t.Fatal("reader replay diagnostics", space["diagnostics"])
		}
		views := agentprofile.Array(space["views"])
		if len(views) != 1 {
			t.Fatal("wrong views")
		}
		view := agentprofile.Object(views[0])
		items := agentprofile.Array(view["items"])
		sources := agentprofile.Array(view["sources"])
		if len(items) != 1 || len(sources) != 1 {
			t.Fatal("lost assertion/source")
		}
		src := agentprofile.Object(sources[0])
		sum := sha256.Sum256([]byte(excerpt))
		if src["object"] != "session:"+room || src["revision"] != "message:"+event || src["issuer"] != "agent:owner" || src["availability"] != "unavailable" || !reflect.DeepEqual(src["digest"], map[string]any{"algorithm": "sha256-bytes-v1", "value": hex.EncodeToString(sum[:])}) {
			t.Fatal("source attribution changed", src)
		}
		gotExcerpt := agentprofile.Object(src["excerpt"])
		if gotExcerpt["state"] != "present" || gotExcerpt["text"] != excerpt {
			t.Fatal("excerpt changed")
		}
		// Canonical origin must preserve the complete room, including server and port.
		want := `{"message":"` + event + `","runtime":"matrix","session":"` + room + `"}`
		if src["origin"] != want {
			t.Fatal("locator changed", src["origin"])
		}
	}
}

// Enabled attributed replacement preserves a full Matrix locator in its source
// auxiliary and independent-reader view. Named secrets in that auxiliary's room
// or excerpt still refuse atomically; the following valid replacement succeeds.
func TestReviseMatrixSessionLocator(t *testing.T) {
	h := newCLI(t)
	h.connectReader()
	id := "record:matrix-revise"
	h.add(h.owner, id, "Initial observation")
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
	room := "!" + alphabet[:43] + ":example.invalid:8448"
	event := "$" + alphabet[:43]
	secret := "gh" + "p_" + strings.Repeat("aB2cD3", 6)
	for i, row := range []struct{ room, excerpt string }{
		{"!prefix" + secret + "suffix:example.invalid:8448", "benign"},
		{room, "benign " + secret},
	} {
		before := h.writeState(h.owner)
		m, out, stderr := h.input(h.owner, row.excerpt, 3, "revise", id, "--relation", "replace", "--expected-version", "1", "--idempotency-key", "matrix-revise-refused-"+strconv64(int64(i)), "--content", "Replacement observation", "--source-session", "matrix:"+row.room+":"+event, "--source-text", "-")
		found := false
		for _, raw := range agentprofile.Array(agentprofile.Object(m["data"])["findings"]) {
			found = found || agentprofile.Object(raw)["detector"] == "github_token"
		}
		if errorCodeOf(m) != "scan_refused" || !found || strings.Contains(string(out), secret) || strings.Contains(string(stderr), secret) {
			t.Fatal("wrong or unsafe attributed replacement refusal", i)
		}
		h.unchanged(h.owner, before)
	}
	excerpt := "Synthetic revision observation\nwith exact trailing newline.\n"
	before := h.git(h.remote, "rev-parse", "main")
	m, _, _ := h.input(h.owner, excerpt, 0, "revise", id, "--relation", "replace", "--expected-version", "1", "--idempotency-key", "matrix-revise-valid", "--content", "Replacement observation", "--source-session", "matrix:"+room+":"+event, "--source-text", "-")
	data := agentprofile.Object(m["data"])
	if data["version"] != int64(2) || len(agentprofile.Array(agentprofile.Object(data["receipt"])["refs"])) != 4 || h.git(h.remote, "rev-list", "--count", before+"..main") != "1" {
		t.Fatal("replacement and auxiliaries were not one atomic admission", m)
	}
	raw := h.git(h.remote, "show", "main:records/source/"+hex.EncodeToString([]byte(id+":v2:source"))+"/1.json")
	stored, refusal := kernel.DecodeJSON([]byte(raw))
	if refusal != nil {
		t.Fatal("invalid stored source", refusal)
	}
	body := agentprofile.Object(agentprofile.Object(agentprofile.Object(stored)["record"])["body"])
	origin := `{"message":"` + event + `","runtime":"matrix","session":"` + room + `"}`
	sum := sha256.Sum256([]byte(excerpt))
	digest := map[string]any{"algorithm": "sha256-bytes-v1", "value": hex.EncodeToString(sum[:])}
	if body["object"] != "session:"+room || body["revision"] != "message:"+event || body["origin"] != origin || body["excerpt"] != excerpt || !reflect.DeepEqual(body["digest"], digest) {
		t.Fatal("replacement source coordinates or exact excerpt changed", body)
	}
	synced, _ := h.invoke(h.reader, 0, "sync", "--space", "space:test")
	spaces := agentprofile.Array(agentprofile.Object(synced["data"])["spaces"])
	if len(spaces) != 1 || agentprofile.Object(spaces[0])["diagnostic_count"] != int64(0) || len(agentprofile.Array(agentprofile.Object(spaces[0])["diagnostics"])) != 0 {
		t.Fatal("replacement reader sync diagnostics", synced)
	}
	read, _ := h.invoke(h.reader, 0, "explain", id, "--version", "2", "--space", "space:test")
	spaces = agentprofile.Array(agentprofile.Object(read["data"])["spaces"])
	if len(spaces) != 1 || len(agentprofile.Array(agentprofile.Object(spaces[0])["diagnostics"])) != 0 {
		t.Fatal("replacement reader diagnostics", read)
	}
	views := agentprofile.Array(agentprofile.Object(spaces[0])["views"])
	if len(views) != 1 {
		t.Fatal("replacement view missing", read)
	}
	items, sources := agentprofile.Array(agentprofile.Object(views[0])["items"]), agentprofile.Array(agentprofile.Object(views[0])["sources"])
	if len(items) != 1 || agentprofile.Object(agentprofile.Object(items[0])["ref"])["version"] != int64(2) || len(sources) != 1 {
		t.Fatal("replacement version or source missing", read)
	}
	source := agentprofile.Object(sources[0])
	if source["object"] != "session:"+room || source["revision"] != "message:"+event || source["origin"] != origin || source["availability"] != "unavailable" || !reflect.DeepEqual(source["digest"], digest) || !reflect.DeepEqual(source["excerpt"], map[string]any{"state": "present", "text": excerpt}) {
		t.Fatal("replacement source read changed", source)
	}
}

// Refused locator lookalikes and free text leave the signed repository, index
// and runtime unchanged, with redacted findings. A valid adjacent locator write
// proves that the refusal path is not rejecting every attributed write.
func TestWriteLocatorRefusals(t *testing.T) {
	h := newCLI(t)
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
	room := "!" + alphabet[:43] + ":example.invalid"
	event := "$" + alphabet[:43]
	secret := "gh" + "p_" + strings.Repeat("aB2cD3", 6)
	encode := base64.RawURLEncoding.EncodeToString
	jwt := encode([]byte(`{"alg":"HS256"}`)) + "." + encode([]byte(`{"sub":"synthetic"}`)) + "." + encode([]byte(strings.Repeat("x", 24)))
	// Malformed or unpaired source flags retain usage/2 and name the flag without
	// reflecting the supplied value. These refusals also leave state unchanged.
	for _, flags := range [][]string{
		{"--source-session", "runtime:" + secret, "--source-text", "-"},
		{"--source-session", "runtime:session:" + secret},
		{"--source-text", "-"},
	} {
		before := h.writeState(h.owner)
		args := append([]string{"add", "assertion", "--content", "benign", "--idempotency-key", "bad-source"}, flags...)
		m, out, stderr := h.input(h.owner, "benign", 2, args...)
		if errorCodeOf(m) != "usage" || !strings.Contains(string(stderr), "--source-session requires runtime:session:message") || strings.Contains(string(out), secret) || strings.Contains(string(stderr), secret) {
			t.Fatal("wrong or unsafe source usage diagnostic")
		}
		h.unchanged(h.owner, before)
	}
	for i, row := range []struct{ name, locator, content, excerpt, detector string }{
		{"named-invalid", "runtime:session:" + secret, "benign", "benign", "github_token"},
		{"named-lookalike", "matrix:!prefix" + secret + "suffix:example.invalid:" + event, "benign", "benign", "github_token"},
		{"jwt-lookalike", "matrix:!room:prefix" + jwt + "x:" + event, "benign", "benign", "jwt"},
		{"content-neighbour", "matrix:" + room + ":" + event, "locator " + event + " secret " + secret, "benign", "github_token"},
		{"excerpt-neighbour", "matrix:" + room + ":" + event, "benign", "locator " + event + " secret " + secret, "github_token"},
		{"strict-locator-excerpt", "matrix:" + room + ":" + event, "benign", event, "entropy_base64"},
		{"strict-commit-content", "matrix:" + room + ":" + event, strings.Repeat("0123456789abcdef", 3)[:40], "benign", "entropy_hex"},
	} {
		before := h.writeState(h.owner)
		m, out, stderr := h.input(h.owner, row.excerpt, 3, "add", "assertion", "--id", "record:refusal", "--idempotency-key", "locator-refusal:"+strconv64(int64(i)), "--content", row.content, "--source-session", row.locator, "--source-text", "-")
		if errorCodeOf(m) != "scan_refused" || len(agentprofile.Array(agentprofile.Object(m["data"])["findings"])) == 0 {
			t.Fatal(row.name, "wrong refusal", m)
		}
		found := false
		for _, f := range agentprofile.Array(agentprofile.Object(m["data"])["findings"]) {
			found = found || agentprofile.Object(f)["detector"] == row.detector
		}
		if !found {
			t.Fatal(row.name, "missing expected detector", row.detector, m)
		}
		for _, value := range []string{secret, jwt} {
			if strings.Contains(string(out), value) || strings.Contains(string(stderr), value) {
				t.Fatal(row.name, "secret leaked")
			}
		}
		h.unchanged(h.owner, before)
	}
	h.input(h.owner, "Benign multiline\nexcerpt.\n", 0, "add", "assertion", "--idempotency-key", "locator-control", "--content", "Valid after refusals", "--source-session", "matrix:"+room+":"+event, "--source-text", "-")
}

// Malformed Matrix coordinates fail as value-free usage/2 before admission on
// add and enabled replace/correct, preserving write state and every cache byte.
// Low-entropy witnesses isolate parsing from scanning; valid hostname/IPv6
// neighbors then
// persist the exact room/server/port/event without repartitioning.
func TestMalformedMatrixSessionUsage(t *testing.T) {
	for _, mode := range []string{"add", "replace", "correct"} {
		t.Run(mode, func(t *testing.T) {
			h := newCLI(t)
			id := "record:matrix-grammar"
			if mode != "add" {
				h.add(h.owner, id, "Initial observation")
			}
			cacheState := func() map[string]string {
				t.Helper()
				space, e := selectSpace(h.config(h.owner), "space:test")
				if e != nil {
					t.Fatal(e)
				}
				files := map[string]string{}
				e = filepath.WalkDir(space.CachePath, func(path string, d os.DirEntry, e error) error {
					if e != nil {
						return e
					}
					if d.IsDir() {
						files[path] = "directory"
						return nil
					}
					b, e := os.ReadFile(path)
					files[path] = "file:" + string(b)
					return e
				})
				if e != nil {
					t.Fatal(e)
				}
				return files
			}
			event := "$" + strings.Repeat("a", 43)
			high := "$ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq"
			malformed := []string{
				"matrix:!room:example.invalid:65536:" + event,
				"matrix:!room:bad..host:" + event,
				"matrix:!room:example.invalid:$short",
				"matrix:!room:[not-ip]:" + event,
				"matrix:!room:example.invalid:" + high[:43],
				"matrix:!room:example.invalid:" + high + "x",
				"matrix:!room:example.invalid:" + high[:43] + "+",
				"matrix:!room:example.invalid:" + high + ".extra",
			}
			args := func(key string, version int) []string {
				if mode == "add" {
					return []string{"add", "assertion", "--id", id + ":" + key, "--content", "An observation", "--idempotency-key", key}
				}
				return []string{"revise", id, "--relation", mode, "--expected-version", strconv64(int64(version)), "--content", "A revision", "--idempotency-key", key}
			}
			for i, locator := range malformed {
				before := h.writeState(h.owner)
				cacheBefore := cacheState()
				flags := append(args("malformed-"+strconv64(int64(i)), 1), "--source-session", locator, "--source-text", "-")
				m, out, stderr := h.input(h.owner, "benign", 2, flags...)
				if errorCodeOf(m) != "usage" || string(stderr) != "memory: usage: --source-session requires runtime:session:message and --source-text FILE|-\n" || strings.Contains(string(out), locator) || m["data"] != nil {
					t.Fatal("wrong or unsafe Matrix usage rejection", i, m)
				}
				h.unchanged(h.owner, before)
				if !reflect.DeepEqual(cacheState(), cacheBefore) {
					t.Fatal("Matrix usage refusal changed cache files or bytes", i)
				}
			}
			for i, room := range []string{"!room:example.invalid:65535", "!room:[2001:db8::1]:8448"} {
				key := "valid-matrix-" + strconv64(int64(i))
				flags := append(args(key, i+1), "--source-session", "matrix:"+room+":"+event, "--source-text", "-")
				h.input(h.owner, "benign", 0, flags...)
				sourceID := id + ":" + key + ":source"
				if mode != "add" {
					sourceID = id + ":v" + strconv64(int64(i+2)) + ":source"
				}
				raw := h.git(h.remote, "show", "main:records/source/"+hex.EncodeToString([]byte(sourceID))+"/1.json")
				stored, refusal := kernel.DecodeJSON([]byte(raw))
				if refusal != nil {
					t.Fatal("invalid stored source", refusal)
				}
				body := agentprofile.Object(agentprofile.Object(agentprofile.Object(stored)["record"])["body"])
				origin := `{"message":"` + event + `","runtime":"matrix","session":"` + room + `"}`
				if body["object"] != "session:"+room || body["revision"] != "message:"+event || body["origin"] != origin {
					t.Fatal("valid Matrix coordinates changed", body)
				}
			}
		})
	}
}
