package scan_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/relux-works/swarma-memory/go/kernel"
	"github.com/relux-works/swarma-memory/go/scan"
)

var roomy = scan.Limits{MaxCanonicalBytes: 1 << 20, MaxStringBytes: 1 << 18, MaxArrayLength: 10000}

type plant struct {
	name     string
	detector scan.Detector
	hit      string
	miss     string
}

// Plants are synthetic, deliberately repetitive, and built at runtime so no
// credential-shaped string is stored in the public repository. JWTs encode only
// a synthetic claim and an all-zero signature; no key material is ever used.
func plants() []plant {
	r := strings.Repeat
	jwt := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`)) + "." +
		base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"synthetic-example"}`)) + "." +
		base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	return []plant{
		{"aws-permanent", scan.AWSAccessKey, "AK" + "IA" + r("A", 16), "AK" + "IA" + r("A", 15)},
		{"aws-temporary", scan.AWSAccessKey, "AS" + "IA" + r("2", 16), "AS" + "IA" + r("a", 16)},
		{"github-classic", scan.GitHubToken, "gh" + "p_" + r("a", 36), "gh" + "p_" + r("a", 37)},
		{"github-fine", scan.GitHubToken, "github_" + "pat_" + r("a", 22) + "_" + r("b", 59), "github_" + "pat_" + r("a", 22) + "_" + r("b", 58)},
		{"github-oauth", scan.GitHubToken, "gh" + "o_" + r("a", 36), "gh" + "o_" + r("a", 18) + "!" + r("a", 17)},
		{"slack-bot", scan.SlackToken, "xo" + "xb-" + r("1", 12) + "-" + r("2", 12) + "-" + r("a", 24), "xo" + "xb-" + r("a", 19)},
		{"slack-user", scan.SlackToken, "xo" + "xp-" + r("1", 12) + "-" + r("2", 12) + "-" + r("3", 12) + "-" + r("a", 32), "xo" + "xp-" + r("a", 10) + "!" + r("a", 10)},
		{"slack-app", scan.SlackToken, "xa" + "pp-" + r("a", 30), "xa" + "pp-" + r("a", 19)},
		{"slack-workflow", scan.SlackToken, "xw" + "fp-" + r("a", 30), "xw" + "fp-" + r("a", 19)},
		{"stripe-live", scan.StripeKey, "sk_" + "live_" + r("a", 24), "sk_" + "live_" + r("a", 23)},
		{"stripe-restricted", scan.StripeKey, "rk_" + "test_" + r("b", 24), "rk_" + "test_" + r("b", 12) + "!" + r("b", 11)},
		{"google", scan.GoogleAPIKey, "AI" + "za" + r("a", 35), "AI" + "za" + r("a", 36)},
		{"openai-classic", scan.OpenAIKey, "s" + "k-" + r("a", 48), "s" + "k-" + r("a", 47)},
		{"openai-project", scan.OpenAIKey, "sk-" + "proj-" + r("a", 156), "sk-" + "proj-" + r("a", 31)},
		{"openai-service", scan.OpenAIKey, "sk-" + "svcacct-" + r("b", 64), "sk-" + "svcacct-" + r("b", 16) + "!" + r("b", 15)},
		{"anthropic", scan.AnthropicKey, "sk-" + "ant-" + "api03-" + r("a", 95), "sk-" + "ant-" + "api03-" + r("a", 31)},
		{"anthropic-admin", scan.AnthropicKey, "sk-" + "ant-" + "admin01-" + r("b", 64), "sk-" + "ant-" + "admin01-" + r("b", 16) + "!" + r("b", 15)},
		{"jwt", scan.JWT, jwt, "not-a-header.not-a-payload." + r("a", 20)},
		{"bearer", scan.Bearer, "Bear" + "er " + r("a", 8), "Bear" + "er \t"},
		{"bearer-case", scan.Bearer, "bEAR" + "ER\ta.a~+/_-=", "Bearers " + r("a", 8)},
		{"url-password", scan.URLPassword, "https://synthetic:" + "fake-password" + "@example.invalid/path", "https://synthetic@example.invalid/path"},
		{"url-encoded-password", scan.URLPassword, "postgresql://synthetic:" + "p%40ss" + "@example.invalid/db", "https://synthetic:@example.invalid/path"},
		{"pem", scan.PrivateKey, "-----BEGIN " + "PRIVATE KEY-----\nAAAA\n-----END " + "PRIVATE KEY-----", "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----"},
		{"pem-openssh", scan.PrivateKey, "-----BEGIN " + "OPENSSH PRIVATE KEY-----\nAAAA", "-----BEGIN OPENSSH PUBLIC KEY-----\nAAAA"},
		{"pem-encrypted", scan.PrivateKey, "-----BEGIN " + "ENCRYPTED PRIVATE KEY-----\nAAAA", "-----BEGIN ENCRYPTED PUBLIC KEY-----\nAAAA"},
		{"pem-other", scan.PrivateKey, "-----BEGIN " + "FUTURE-ALGORITHM PRIVATE KEY-----", "-----BEGIN FUTURE-ALGORITHM PUBLIC KEY-----"},
		{"hex-entropy", scan.EntropyHex, r("0123456789abcdef", 4), r("a", 64)},
		{"base64-entropy", scan.EntropyBase64, "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + "abcdefghijklmnopqrstuvwxyz0123456789+/", r("z", 64)},
	}
}

func has(findings []scan.Finding, detector scan.Detector) bool {
	for _, finding := range findings {
		if finding.Detector == detector {
			return true
		}
	}
	return false
}

// TestDetectorControls proves each synthetic format is detected as a standalone
// value, embedded in prose, and as a deep object key; its stated near-miss passes
// the entire scan. This is format coverage, not credential validity verification.
func TestDetectorControls(t *testing.T) {
	for _, p := range plants() {
		t.Run(p.name, func(t *testing.T) {
			for _, value := range []any{p.hit, "example: '" + p.hit + "'; end", map[string]any{"outer": []any{map[string]any{p.hit: nil}}}} {
				if !has(scan.Scan(value, roomy), p.detector) {
					t.Fatal("plant missed by", p.detector)
				}
			}
			if got := scan.Scan(p.miss, roomy); len(got) != 0 {
				t.Fatal("near-miss refused", got)
			}
		})
	}
}

// TestNoSecretInFindings proves JSON and formatted findings contain neither a
// complete synthetic secret, including key
// findings and descendants. No input fragments are used in redacted excerpts.
func TestNoSecretInFindings(t *testing.T) {
	for _, p := range plants() {
		t.Run(p.name, func(t *testing.T) {
			value := map[string]any{"safe": []any{map[string]any{p.hit: map[string]any{"child": p.hit}}}, "value": p.hit}
			got := scan.Scan(value, roomy)
			raw, err := json.Marshal(got)
			if err != nil || len(got) == 0 {
				t.Fatal("missing or unencodable findings")
			}
			encoded, _ := json.Marshal(p.hit)
			if bytes.Contains(raw, []byte(p.hit)) || bytes.Contains(raw, encoded[1:len(encoded)-1]) || strings.Contains(fmt.Sprint(got), p.hit) {
				t.Fatal("findings disclosed a synthetic secret")
			}
			var key, descendant bool
			for _, f := range got {
				if f.Excerpt != "[REDACTED]" {
					t.Fatal("excerpt contains input content")
				}
				if f.Detector == p.detector && (f.Pointer == "/safe/0" || f.Pointer == "/safe") && f.PointerRedacted {
					key = key || f.InKey
					descendant = descendant || !f.InKey
				}
			}
			if !key || !descendant {
				t.Fatal("unsafe-key pointers were not anchored to the safe ancestor", got)
			}
		})
	}
}

// TestEntropyBoundaries proves the documented inclusive minima and thresholds
// for these known distributions; punctuation-separated candidates are scanned.
func TestEntropyBoundaries(t *testing.T) {
	tests := []struct {
		name string
		text string
		want scan.Detector
	}{
		{"hex-under-length", strings.Repeat("0123456789abcdef", 2)[:31], ""},
		{"hex-at-length", strings.Repeat("0123456789abcdef", 2), scan.EntropyHex},
		{"hex-at-threshold", strings.Repeat("01234567", 4), scan.EntropyHex},
		{"hex-under-threshold", strings.Repeat("0123456", 8), ""},
		{"base64-under-length", "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + "ghijk", ""},
		{"base64-at-length", "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + "ghijkl", scan.EntropyBase64},
		{"base64-under-threshold", strings.Repeat("ABCDEFGHIJKLMNOPQRSTUV", 2), ""},
		{"base64-over-threshold", strings.Repeat("ABCDEFGHIJKLMNOPQRSTUVW", 2), scan.EntropyBase64},
		{"base64url", "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + "abcdefghijklmnopqrstuvwxyz0123456789_-", scan.EntropyBase64},
		{"base64-padding", "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + "abcdefghijklmnopqrstuvwxyz0123456789+/==", scan.EntropyBase64},
		{"embedded-hex", "hash: " + strings.Repeat("0123456789abcdef", 4) + ";", scan.EntropyHex},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := scan.Scan(test.text, roomy)
			if test.want == "" && len(got) != 0 || test.want != "" && !has(got, test.want) {
				t.Fatal("unexpected entropy verdict", got)
			}
		})
	}
}

// TestExemptions proves only complete values at the declared paths bypass
// entropy. Moving the same value to ordinary content (or using a digest-like
// key), adding text, or planting a known token must still be refused.
func TestExemptions(t *testing.T) {
	digest := strings.Repeat("0123456789abcdef", 4)
	handle := digest[:32]
	tests := []struct {
		name  string
		value any
	}{
		{"output-digest", map[string]any{"output_digest": digest}},
		{"body-output-digest", map[string]any{"body": map[string]any{"declassification": map[string]any{"output_digest": digest}}}},
		{"bare-declassification", map[string]any{"declassification": map[string]any{"output_digest": digest}}},
		{"source-digest", map[string]any{"body": map[string]any{"digest": map[string]any{"algorithm": "sha256-cjson-v1", "value": digest}}}},
		{"bytes-source-digest", map[string]any{"body": map[string]any{"digest": map[string]any{"algorithm": "sha256-bytes-v1", "value": digest}}}},
		{"bare-bytes-source-digest", map[string]any{"digest": map[string]any{"algorithm": "sha256-bytes-v1", "value": digest}}},
		{"bare-source-digest", map[string]any{"digest": map[string]any{"algorithm": "sha256-cjson-v1", "value": digest}}},
		{"locator", map[string]any{"locator": "sha256:" + digest}},
		{"source-object", map[string]any{"body": map[string]any{"object": "sha256:" + digest}}},
		{"snapshot-handle", map[string]any{"authorized_snapshot_handle": handle}},
		{"receipt-handle", map[string]any{"receipt_handle": handle}},
		{"body-handle", map[string]any{"body": map[string]any{"receipt_handle": handle}}},
		{"uuid", "12345678-9abc-def0-1234-56789abcdef0"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := scan.Scan(test.value, roomy); len(got) != 0 {
				t.Fatal("declared exemption refused", got)
			}
		})
	}
	for name, value := range map[string]any{
		"ordinary-digest":     map[string]any{"content": digest},
		"ordinary-handle":     map[string]any{"content": handle},
		"ordinary-locator":    map[string]any{"content": "sha256:" + digest},
		"fake-digest-role":    map[string]any{"nested": map[string]any{"output_digest": digest}},
		"fake-handle-role":    map[string]any{"nested": map[string]any{"receipt_handle": handle}},
		"digest-key":          map[string]any{digest: nil},
		"missing-algorithm":   map[string]any{"digest": map[string]any{"value": digest}},
		"wrong-algorithm":     map[string]any{"digest": map[string]any{"algorithm": "other", "value": digest}},
		"extra-text":          map[string]any{"output_digest": digest + " more"},
		"oversized-digest":    map[string]any{"output_digest": digest + digest},
		"wrong-handle-length": map[string]any{"receipt_handle": digest},
	} {
		t.Run(name, func(t *testing.T) {
			if got := scan.Scan(value, roomy); !has(got, scan.EntropyHex) {
				t.Fatal("entropy exemption widened", got)
			}
		})
	}
	for _, p := range plants() {
		if p.detector == scan.EntropyHex || p.detector == scan.EntropyBase64 {
			continue
		}
		if !has(scan.Scan(map[string]any{"output_digest": p.hit}, roomy), p.detector) {
			t.Fatal("digest role hid a known secret", p.name)
		}
	}
}

// TestSizeLimits proves exact inclusive limits and one-byte/element overflow
// independently, including canonical escaping, UTF-8, keys, arrays at depth,
// zero caps, and size checks on entropy-exempt fields.
func TestSizeLimits(t *testing.T) {
	tests := []struct {
		name  string
		value any
		at    scan.Limits
		over  scan.Limits
		want  scan.Detector
	}{
		{"canonical", "\n", scan.Limits{4, 100, 100}, scan.Limits{3, 100, 100}, scan.CanonicalSize},
		{"string", "é", scan.Limits{100, 2, 100}, scan.Limits{100, 1, 100}, scan.StringSize},
		{"object-key", map[string]any{"é": nil}, scan.Limits{100, 2, 100}, scan.Limits{100, 1, 100}, scan.StringSize},
		{"array", map[string]any{"a": []any{nil, nil}}, scan.Limits{100, 100, 2}, scan.Limits{100, 100, 1}, scan.ArraySize},
		{"digest", map[string]any{"output_digest": strings.Repeat("0123456789abcdef", 4)}, scan.Limits{1000, 64, 100}, scan.Limits{1000, 63, 100}, scan.StringSize},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := scan.Scan(test.value, test.at); len(got) != 0 {
				t.Fatal("exact boundary refused", got)
			}
			got := scan.Scan(test.value, test.over)
			if len(got) != 1 || got[0].Detector != test.want {
				t.Fatal("overflow did not get its precise finding", got)
			}
		})
	}
	for _, value := range []any{"", []any{}, map[string]any{}} {
		if got := scan.Scan(value, scan.Limits{100, 0, 0}); len(got) != 0 {
			t.Fatal("empty value refused by zero string/array cap", got)
		}
	}
	if !has(scan.Scan("", scan.Limits{}), scan.CanonicalSize) || !has(scan.Scan("a", scan.Limits{100, 0, 0}), scan.StringSize) || !has(scan.Scan([]any{nil}, scan.Limits{100, 0, 0}), scan.ArraySize) {
		t.Fatal("zero cap was treated as unlimited")
	}
	p := plants()[0]
	got := scan.Scan(map[string]any{"a": []any{p.hit}}, scan.Limits{1, 1, 0})
	for _, detector := range []scan.Detector{scan.CanonicalSize, scan.ArraySize, scan.StringSize, p.detector} {
		if !has(got, detector) {
			t.Fatal("size finding suppressed another check", detector)
		}
	}
}

// TestInvalidInputs proves invalid limits/Go value types refuse with redacted
// root findings, while kernel's decoded types and kernel.Record remain accepted.
func TestInvalidInputs(t *testing.T) {
	for _, limits := range []scan.Limits{{-1, 1, 1}, {1, -1, 1}, {1, 1, -1}} {
		if got := scan.Scan(nil, limits); len(got) != 1 || got[0].Detector != scan.InvalidLimits || got[0].Pointer != "" {
			t.Fatal("invalid limit did not fail closed", got)
		}
	}
	for _, value := range []any{1, 1.5, []string{"text"}, map[string]any{"bad": string([]byte{0xff})}, int64(9007199254740992)} {
		if got := scan.Scan(value, roomy); len(got) != 1 || got[0].Detector != scan.InvalidJSON || got[0].Pointer != "" {
			t.Fatal("invalid JSON model did not fail closed", got)
		}
	}
	for _, value := range []any{nil, true, int64(1), "text", []any{false}, map[string]any{"a": nil}, kernel.Record{"body": nil}} {
		if got := scan.Scan(value, roomy); got != nil {
			t.Fatal("kernel JSON type refused", got)
		}
	}
}

// TestPointersAndDeterminism proves escaped RFC 6901 paths, pointer/detector
// sorting, repeated-match coalescing, repeatability, and unchanged input bytes.
func TestPointersAndDeterminism(t *testing.T) {
	a, b := plants()[0], plants()[3]
	value := map[string]any{"z": a.hit, "a/~": []any{b.hit + " " + a.hit + " " + a.hit}}
	before, _ := kernel.CanonicalJSON(value)
	want := scan.Scan(value, roomy)
	if len(want) != 3 || want[0].Pointer != "/a~1~0/0" || want[0].Detector != scan.AWSAccessKey || want[1].Detector != scan.GitHubToken || want[2].Pointer != "/z" {
		t.Fatal("paths, sorting or per-location coalescing changed", want)
	}
	for range 20 {
		if got := scan.Scan(value, roomy); !reflect.DeepEqual(got, want) {
			t.Fatal("nondeterministic findings")
		}
	}
	after, _ := kernel.CanonicalJSON(value)
	if !bytes.Equal(before, after) {
		t.Fatal("scanner mutated its input")
	}
}

// TestCorpusFalsePositives scans every initial record body and complete record
// in the semantic corpus and domain fixtures. Zero hits is a corpus observation,
// not proof that arbitrary non-sensitive input will be accepted.
func TestCorpusFalsePositives(t *testing.T) {
	files, err := filepath.Glob("../../spec/kernel/vectors/semantic/*.json")
	if err != nil || len(files) != 77 {
		t.Fatal("semantic corpus absent or changed")
	}
	semanticFiles := len(files)
	err = filepath.WalkDir("../../spec/domains", func(path string, entry fs.DirEntry, err error) error {
		if err == nil && !entry.IsDir() && entry.Name() == "fixture.json" {
			files = append(files, path)
		}
		return err
	})
	if err != nil || len(files) == semanticFiles {
		t.Fatal("domain fixtures absent or unreadable")
	}
	var records, hits int
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		value, refusal := kernel.DecodeJSON(data)
		if refusal != nil {
			t.Fatal("corpus JSON refused", file)
		}
		state := value.(map[string]any)["initial_state"].(map[string]any)
		for _, record := range state["records"].([]any) {
			records++
			for _, part := range []any{record, record.(map[string]any)["body"]} {
				got := scan.Scan(part, roomy)
				hits += len(got)
				if len(got) > 0 {
					t.Errorf("corpus finding in %s record %d: %+v", file, records, got)
				}
			}
		}
	}
	t.Logf("%d semantic files; %d domain fixtures; %d records, scanned as full record and body (%d scans); %d findings", semanticFiles, len(files)-semanticFiles, records, records*2, hits)
}

// TestJWTNeighbours proves JSON whitespace and dotted prose prefixes do not hide
// a compact JWT, while malformed header/claims/signature and unsigned HS256
// tokens do not qualify as JWTs. An explicit alg=none compact JWT is detected.
func TestJWTNeighbours(t *testing.T) {
	encode := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	header := encode(`{"alg":"HS256"}`)
	claims := encode(" \n{\"sub\":\"synthetic\"} \n")
	signature := encode("fake-signature")
	valid := header + "." + claims + "." + signature
	for _, text := range []string{valid, "prefix." + valid, "prefix.one." + valid, "'" + valid + "'.", encode(`{"alg":"none"}`) + "." + claims + "."} {
		if !has(scan.Scan(text, roomy), scan.JWT) {
			t.Fatal("JWT neighbour missed")
		}
	}
	for _, text := range []string{encode(`{"typ":"JWT"}`) + "." + claims + "." + signature, header + "." + encode(`[]`) + "." + signature, header + "." + claims + ".", header + "." + claims + ".a", "wrong." + claims + "." + signature} {
		if has(scan.Scan(text, roomy), scan.JWT) {
			t.Fatal("malformed compact value qualified as JWT")
		}
	}
}

// TestPrivateKeyLabels proves arbitrary PEM algorithm labels and truncated
// private-key blocks refuse without requiring a valid key or a closing marker;
// the corresponding public-key header passes these synthetic low-entropy bodies.
func TestPrivateKeyLabels(t *testing.T) {
	for _, label := range []string{"RSA", "EC", "DSA", "OPENSSH", "ENCRYPTED", "NEW_ALGORITHM.1/+"} {
		private := "-----BEGIN " + label + " PRIVATE" + " KEY-----\nAAAA"
		public := "-----BEGIN " + label + " PUBLIC KEY-----\nAAAA"
		if !has(scan.Scan(private, roomy), scan.PrivateKey) {
			t.Fatal("private-key label missed")
		}
		if got := scan.Scan(public, roomy); len(got) != 0 {
			t.Fatal("public-key control refused", got)
		}
	}
}

// TestPointerSubstringRedaction proves a finding cannot leak a detected secret
// through a different key that contains it without token boundaries. Bearer and
// URL password values are also protected separately from their surrounding syntax.
func TestPointerSubstringRedaction(t *testing.T) {
	p := plants()[0]
	for _, test := range []struct {
		secret string
		value  string
	}{
		{p.hit, p.hit},
		{"synthetic-password", "https://synthetic:" + "synthetic-password" + "@example.invalid"},
		{"synthetic-token", "Bear" + "er synthetic-token"},
	} {
		value := map[string]any{"safe": map[string]any{"prefix" + test.secret + "suffix": map[string]any{"v": test.value}}}
		got := scan.Scan(value, roomy)
		raw, _ := json.Marshal(got)
		if len(got) == 0 || bytes.Contains(raw, []byte(test.secret)) {
			t.Fatal("secret leaked through another key")
		}
		for _, f := range got {
			if f.Pointer != "/safe" || !f.PointerRedacted {
				t.Fatal("substring-bearing ancestor not redacted", f)
			}
		}
	}
}

// TestPointerEncodingRedaction proves RFC 6901 escaping and joining path
// segments cannot recreate a detected bearer value in the reported pointer.
func TestPointerEncodingRedaction(t *testing.T) {
	for _, test := range []struct {
		value any
		want  string
	}{
		{map[string]any{"abc/def": "Bear" + "er abc~1def"}, ""},
		{map[string]any{"abc": map[string]any{"def": "Bear" + "er abc/def"}}, ""},
	} {
		got := scan.Scan(test.value, roomy)
		if len(got) != 1 || got[0].Pointer != test.want || !got[0].PointerRedacted {
			t.Fatal("encoding recreated a credential in a pointer", got)
		}
	}
}

// TestAllMatchesRedacted proves later matches of the same detector are protected
// too: a preceding match must not stop collection of spans needed for redaction.
func TestAllMatchesRedacted(t *testing.T) {
	first := plants()[0].hit
	second := "AK" + "IA" + strings.Repeat("B", 16)
	value := map[string]any{"prefix" + second + "suffix": first + " " + second}
	got := scan.Scan(value, roomy)
	raw, _ := json.Marshal(got)
	if len(got) == 0 || bytes.Contains(raw, []byte(second)) {
		t.Fatal("a later match leaked through a pointer")
	}
}

// TestSplitSecretLocations proves that finding pointers expose no four-byte
// fragment of detected values or their credential components, either directly
// or after RFC 6901 decoding and joining. Runtime plants cover all secret
// detector kinds, provider variants, and split lengths below/at/above four.
func TestSplitSecretLocations(t *testing.T) {
	for _, p := range plants() {
		components := []string{p.hit}
		switch p.detector {
		case scan.Bearer:
			components = append(components, strings.TrimSpace(p.hit[len("Bearer"):]))
		case scan.URLPassword:
			userinfo := p.hit[strings.Index(p.hit, "://")+3 : strings.Index(p.hit, "@")]
			components = append(components, userinfo[strings.Index(userinfo, ":")+1:])
		case scan.PrivateKey:
			// This low-entropy payload does not independently trigger entropy:
			// header detection must still protect the entire private-key string.
			components = append(components, strings.Repeat("synthetic-material", 3))
		}
		for componentIndex, component := range components {
			for _, width := range []int{1, 2, 3, 4, 5, 8, 13} {
				t.Run(fmt.Sprintf("%s/component-%d/split-%d", p.name, componentIndex, width), func(t *testing.T) {
					leaf := p.hit
					if p.detector == scan.PrivateKey {
						leaf += "\n" + strings.Repeat("synthetic-material", 3)
					}
					var nested any = leaf
					var segments []string
					for start := 0; start < len(component); start += width {
						segments = append(segments, component[start:min(start+width, len(component))])
					}
					for i := len(segments) - 1; i >= 0; i-- {
						nested = map[string]any{segments[i]: nested}
					}
					got := scan.Scan(map[string]any{"safe": nested}, roomy)
					if !has(got, p.detector) {
						t.Fatal("positive detector control failed")
					}
					raw, _ := json.Marshal(got)
					for _, f := range got {
						var decodedSegments []string
						if f.Pointer != "" {
							for _, segment := range strings.Split(f.Pointer[1:], "/") {
								decodedSegments = append(decodedSegments, strings.ReplaceAll(strings.ReplaceAll(segment, "~1", "/"), "~0", "~"))
							}
						}
						decoded := strings.Join(decodedSegments, "/")
						joined := strings.Join(decodedSegments, "")
						for offset := 0; offset+4 <= len(component); offset++ {
							fragment := component[offset : offset+4]
							// JSON field names and fixed detector labels are public
							// metadata. Check data-bearing excerpts/pointers in raw
							// JSON, then decoded and separator-free path material.
							location, _ := json.Marshal(struct{ Pointer, Excerpt string }{f.Pointer, f.Excerpt})
							if bytes.Contains(location, []byte(fragment)) || strings.Contains(decoded, fragment) || strings.Contains(joined, fragment) {
								t.Fatal("recoverable credential fragment in finding location")
							}
						}
						if !f.PointerRedacted {
							t.Fatal("unsafe path lacks redaction marker")
						}
					}
					if bytes.Contains(raw, []byte(component)) {
						t.Fatal("complete credential component in raw findings")
					}
				})
			}
		}
	}
}

// TestSafeAncestorDepth proves benign paths remain exact and a partially unsafe
// path retains only its safe ancestor plus a deterministic, content-free depth.
func TestSafeAncestorDepth(t *testing.T) {
	p := plants()[0]
	safe := scan.Scan(map[string]any{"outer": map[string]any{"value": p.hit}}, roomy)
	if len(safe) != 1 || safe[0].Pointer != "/outer/value" || safe[0].PointerRedacted || safe[0].OriginalDepth != 0 {
		t.Fatal("safe path lost its location", safe)
	}
	value := map[string]any{"outer": map[string]any{p.hit[:8]: map[string]any{"value": p.hit}}}
	got := scan.Scan(value, roomy)
	if len(got) != 1 || got[0].Pointer != "/outer" || !got[0].PointerRedacted || got[0].OriginalDepth != 3 {
		t.Fatal("unsafe contributor or original depth leaked", got)
	}
	for range 10 {
		if !reflect.DeepEqual(scan.Scan(value, roomy), got) {
			t.Fatal("redacted locations are nondeterministic")
		}
	}
}

// TestShortFragmentPermutation proves short credential pieces are not exposed
// merely because their path order changes. Only the benign ancestor survives.
func TestShortFragmentPermutation(t *testing.T) {
	p := plants()[0]
	for _, width := range []int{1, 2, 3} {
		var nested any = p.hit
		for start := 0; start < len(p.hit); start += width {
			nested = map[string]any{p.hit[start:min(start+width, len(p.hit))]: nested}
		}
		got := scan.Scan(map[string]any{"outer": nested}, roomy)
		if !has(got, p.detector) {
			t.Fatal("detector positive control failed")
		}
		for _, f := range got {
			if f.Pointer != "/outer" || !f.PointerRedacted {
				t.Fatal("permuted short credential pieces exposed")
			}
		}
	}
}
