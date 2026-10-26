package scan_test

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/relux-works/swarma-memory/go/scan"
)

func locatorFixture() (string, string) {
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
	return "!" + alphabet[:43] + ":example.invalid:8448", "$" + alphabet[:43]
}
func locatorRecord() map[string]any {
	return map[string]any{"envelope": map[string]any{"kind": "source"}, "body": map[string]any{"source_kind": "artifact", "owner": "synthetic", "object": "artifact:synthetic", "revision": "1", "origin": "artifact:synthetic", "excerpt": "benign"}}
}
func locatorBody(r map[string]any) map[string]any { return r["body"].(map[string]any) }
func sessionRecord(room, event string) map[string]any {
	r := locatorRecord()
	b := locatorBody(r)
	origin, _ := json.Marshal(map[string]any{"runtime": "matrix", "session": room, "message": event})
	b["owner"], b["object"], b["revision"], b["origin"] = "runtime:matrix", "session:"+room, "message:"+event, string(origin)
	return r
}

// Exact declared source locator roles bypass only entropy. Moving the same
// high-entropy bytes to an excerpt still refuses, and every row has a named-token
// control. UUIDs retain the pre-existing global heuristic, including free text.
func TestSourceLocatorExemptions(t *testing.T) {
	room, event := locatorFixture()
	digest := strings.Repeat("0123456789abcdef", 4)
	for _, row := range []struct {
		name, value string
		detector    scan.Detector
	}{
		{"event", event, scan.EntropyBase64}, {"room", room, scan.EntropyBase64},
		{"commit40", digest[:40], scan.EntropyHex}, {"commit64", digest, scan.EntropyHex},
		{"sha256", "sha256:" + digest, scan.EntropyHex}, {"uuid", "12345678-9abc-def0-1234-56789abcdef0", ""},
	} {
		t.Run(row.name, func(t *testing.T) {
			for _, field := range []string{"object", "origin", "revision"} {
				r := locatorRecord()
				b := locatorBody(r)
				b[field] = row.value
				if got := scan.Scan(r, roomy); len(got) != 0 {
					t.Fatal(field, "exact locator refused", got)
				}
				b["excerpt"] = row.value
				if row.detector != "" && !has(scan.Scan(r, roomy), row.detector) {
					t.Fatal("free-text entropy bypass", field)
				}
				b["excerpt"] = plants()[2].hit
				if !has(scan.Scan(r, roomy), scan.GitHubToken) {
					t.Fatal("locator disabled the scanner", field)
				}
			}
		})
	}
	if got := scan.Scan(sessionRecord(room, event), roomy); len(got) != 0 {
		t.Fatal("structured session refused", got)
	}
}

// Known-format tokens remain refused even inside a syntactically valid room
// localpart without token boundaries. This specifically detects a blanket
// entropy/secret bypass and the old bounded-match lookalike failure class.
func TestLocatorNamedTokens(t *testing.T) {
	_, event := locatorFixture()
	alphabet := regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	for _, p := range plants() {
		if p.detector == scan.EntropyHex || p.detector == scan.EntropyBase64 {
			continue
		}
		r := locatorRecord()
		locatorBody(r)["object"] = p.hit
		if !has(scan.Scan(r, roomy), p.detector) {
			t.Fatal("invalid grammar hid named secret", p.name)
		}
		if !alphabet.MatchString(p.hit) || len(p.hit) > 210 {
			continue
		}
		room := "!prefix" + p.hit + "suffix:example.invalid"
		if _, _, _, ok := scan.ParseSessionLocator("matrix:" + room + ":" + event); !ok {
			t.Fatal("lookalike plant was not applied", p.name)
		}
		for _, field := range []string{"object", "origin", "revision"} {
			r = locatorRecord()
			locatorBody(r)[field] = room
			if !has(scan.Scan(r, roomy), p.detector) {
				t.Fatal("exact locator hid embedded named secret", p.name, field)
			}
		}
		if !has(scan.Scan(sessionRecord(room, event), roomy), p.detector) {
			t.Fatal("structured origin hid named secret", p.name)
		}
	}
}

// Nonmatching forms receive the original scanner, including malformed lengths,
// alphabet and suffixes. Malformed syntax alone is not a secret verdict; these
// witnesses deliberately retain entropy above the original detector thresholds.
func TestLocatorNearMissesAndRoles(t *testing.T) {
	room, event := locatorFixture()
	digest := strings.Repeat("0123456789abcdef", 4)
	for _, row := range []struct {
		name, value string
		detector    scan.Detector
	}{
		{"event-short", event[:43], scan.EntropyBase64}, {"event-long", event + "x", scan.EntropyBase64},
		{"event-alphabet", event[:43] + "+", scan.EntropyBase64}, {"event-suffix", event + ".extra", scan.EntropyBase64},
		{"room-server", room + "/path", scan.EntropyBase64}, {"room-long", "!" + strings.Repeat("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-", 5) + ":example.invalid", scan.EntropyBase64},
		{"hash-short", digest[:39], scan.EntropyHex}, {"hash-long", digest + "a", scan.EntropyHex},
		{"digest-suffix", "sha256:" + digest + ".extra", scan.EntropyHex},
	} {
		t.Run(row.name, func(t *testing.T) {
			for _, field := range []string{"object", "origin", "revision"} {
				r := locatorRecord()
				locatorBody(r)[field] = row.value
				if !has(scan.Scan(r, roomy), row.detector) {
					t.Fatal("nonmatching value exempted", field)
				}
			}
		})
	}
	for _, mutate := range []func(map[string]any){
		func(r map[string]any) { r["envelope"].(map[string]any)["kind"] = "assertion" },
		func(r map[string]any) { locatorBody(r)["source_kind"] = "message" },
		func(r map[string]any) { b := locatorBody(r); b["origin"] = " " + b["origin"].(string) },
		func(r map[string]any) { locatorBody(r)["owner"] = "runtime:other" },
		func(r map[string]any) { locatorBody(r)["revision"] = "message:other" },
		func(r map[string]any) {
			b := locatorBody(r)
			b["origin"] = strings.TrimSuffix(b["origin"].(string), "}") + `,"extra":"unused"}`
		},
		func(r map[string]any) {
			b := locatorBody(r)
			b["origin"] = strings.TrimSuffix(b["origin"].(string), "}") + `,"runtime":"matrix"}`
		},
	} {
		r := sessionRecord(room, event)
		mutate(r)
		if !has(scan.Scan(r, roomy), scan.EntropyBase64) {
			t.Fatal("wrong role/nonclosed/inconsistent origin exempted")
		}
	}
	r := locatorRecord()
	locatorBody(r)[event] = "benign"
	if !has(scan.Scan(r, roomy), scan.EntropyBase64) {
		t.Fatal("object key exempted")
	}
	r = locatorRecord()
	locatorBody(r)["object"] = event
	if !has(scan.Scan(r, scan.Limits{MaxCanonicalBytes: 1 << 20, MaxStringBytes: 43, MaxArrayLength: 100}), scan.StringSize) {
		t.Fatal("locator bypassed size cap")
	}
}

// The parser recognizes a closed conservative set, preserving IPv6/port room
// servers and exact UUID/message coordinates. Unsupported forms are not silently
// upgraded into scanner exemptions; callers retain their ordinary input path.
func TestSessionLocatorGrammar(t *testing.T) {
	room, event := locatorFixture()
	uuid := "12345678-9abc-def0-1234-56789abcdef0"
	for _, row := range []struct{ runtime, session, message string }{
		{"matrix", room, event}, {"matrix", "!room:[2001:db8::1]:8448", event},
		{"matrix", "!room:[2001:db8::1]", event}, {"matrix", "!room:127.0.0.1", event},
		{"codex", uuid, uuid}, {"claude", uuid, "message:" + uuid}, {"codex", uuid, "index:17"}, {"claude", uuid, "0"},
	} {
		r, s, m, ok := scan.ParseSessionLocator(row.runtime + ":" + row.session + ":" + row.message)
		if !ok || r != row.runtime || s != row.session || m != row.message {
			t.Fatal("valid grammar changed", row)
		}
	}
	for _, input := range []string{
		"matrix:" + room + ":" + event + "x", "matrix:!room:server/path:" + event,
		"matrix:!room:server:65536:" + event, "matrix:!room:server:+80:" + event,
		"matrix:!room:bad..server:" + event, "matrix:!room:[not-ip]:" + event, "matrix:!room:[not-ip]:80:" + event,
		"matrix:!room:[127.0.0.1]:80:" + event, "matrix:!room:[fe80::1%zone]:80:" + event,
		"matrix:!room:2001:db8::1:" + event, "matrix:!room:server:" + event[:43] + "+",
		"codex:" + uuid + "x:0", "claude:" + uuid + ":index:-1", "claude:" + uuid + ":index:18446744073709551616",
		"runtime:session:message", "codex:" + uuid + ":message:arbitrary",
	} {
		if _, _, _, ok := scan.ParseSessionLocator(input); ok {
			t.Fatal("nonmatching grammar accepted", input)
		}
	}
}
