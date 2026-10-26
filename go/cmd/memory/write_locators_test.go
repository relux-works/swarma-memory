package main

import (
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"strings"
	"testing"

	"github.com/relux-works/swarma-memory/go/agentprofile"
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
	h.invoke(h.reader, 0, "sync", "--space", "space:test")
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

// Refused locator lookalikes and free text leave the signed repository, index
// and runtime unchanged, with redacted findings. A valid adjacent locator write
// proves that the refusal path is not rejecting every attributed write.
func TestWriteLocatorRefusals(t *testing.T) {
	h := newCLI(t)
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
	room := "!" + alphabet[:43] + ":example.invalid"
	event := "$" + alphabet[:43]
	secret := "gh" + "p_" + strings.Repeat("aB2cD3", 6)
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
		{"short", "matrix:" + room + ":" + event[:43], "benign", "benign", "entropy_base64"},
		{"long", "matrix:" + room + ":" + event + "x", "benign", "benign", "entropy_base64"},
		{"alphabet", "matrix:" + room + ":" + event[:43] + "+", "benign", "benign", "entropy_base64"},
		{"suffix", "matrix:" + room + ":" + event + ".extra", "benign", "benign", "entropy_base64"},
		{"named-invalid", "runtime:session:" + secret, "benign", "benign", "github_token"},
		{"named-lookalike", "matrix:!prefix" + secret + "suffix:example.invalid:" + event, "benign", "benign", "github_token"},
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
		if strings.Contains(string(out), secret) || strings.Contains(string(stderr), secret) {
			t.Fatal(row.name, "secret leaked")
		}
		h.unchanged(h.owner, before)
	}
	h.input(h.owner, "Benign multiline\nexcerpt.\n", 0, "add", "assertion", "--idempotency-key", "locator-control", "--content", "Valid after refusals", "--source-session", "matrix:"+room+":"+event, "--source-text", "-")
}
