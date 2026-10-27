package scan_test

import (
	"strings"
	"testing"

	"github.com/relux-works/swarma-memory/go/scan"
)

// A complete short task-ID path segment must not turn adjacent short prose into
// one entropy candidate. No arbitrary slash/base64 splitting is permitted: real
// long candidates, suffix lookalikes, keys, size caps and named tokens stay checked.
func TestEngineeringTokenBoundaries(t *testing.T) {
	id := "TASK-123456-ghijkl"
	compound := "scan_refused3/" + id
	pseudo := "v0.0.0-20260102030405-123456abcdef"
	for _, text := range []string{compound, id + "/scan_refused3", "word/" + id + "/other_word", compound + "/" + id, pseudo, "PR #123 abcdef0 123456abcdef $ABCDEFGH"} {
		if got := scan.Scan(text, roomy); len(got) != 0 {
			t.Fatal("engineering compound refused", got)
		}
		if !has(scan.Scan(text+" "+plants()[2].hit, roomy), scan.GitHubToken) {
			t.Fatal("engineering boundary disabled named scanning")
		}
	}
	secret := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"
	for _, text := range []string{secret, "word/" + secret, secret + "/word", secret + "/" + id, id + "/" + secret, "word/" + secret + "/" + id, strings.Repeat("a", 96) + "/" + secret + "/" + id, "ABCDEFGHIJKLMNOP/QRSTUVWXYZabcdef/" + id, "ABCDEFGHIJKLMNOP/ABCDEFGHIJKLMNO/" + id} {
		if !has(scan.Scan(text, roomy), scan.EntropyBase64) {
			t.Fatal("engineering boundary hid base64 secret")
		}
	}
	hex := strings.Repeat("0123456789abcdef", 3)[:40]
	if !has(scan.Scan(hex+"/"+id, roomy), scan.EntropyHex) {
		t.Fatal("engineering boundary hid hex secret")
	}
	for _, value := range []string{"x" + id, id + "x", "TASK-x23456-ghijkl", "TASK-123456-ghijk", "TASK-123456-ghijklm", "TASK-123456-ghijk_"} {
		if !has(scan.Scan("scan_refused33/"+value, roomy), scan.EntropyBase64) {
			t.Fatal("task-ID near miss gained an exemption")
		}
	}
	if !has(scan.Scan(map[string]any{compound: "benign"}, roomy), scan.EntropyBase64) {
		t.Fatal("engineering key bypassed scanning")
	}
	if !has(scan.Scan(compound, scan.Limits{MaxCanonicalBytes: 1000, MaxStringBytes: 31, MaxArrayLength: 100}), scan.StringSize) {
		t.Fatal("engineering compound bypassed size limit")
	}
	// The pseudoversion already has no 32-byte candidate (its dots split it).
	if !has(scan.Scan(pseudo+" "+secret, roomy), scan.EntropyBase64) {
		t.Fatal("pseudoversion hid a neighbouring secret")
	}
}
