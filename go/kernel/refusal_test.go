package kernel

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// TestRefusalContract proves every K-REF-1 code and retryable flag matches the normative table and serializes to exactly three fields.
func TestRefusalContract(t *testing.T) {
	data, err := os.ReadFile("../../spec/kernel/semantics.md")
	if err != nil {
		t.Fatal(err)
	}
	_, section, found := strings.Cut(string(data), "### K-REF-1")
	if !found {
		t.Fatal("missing K-REF-1 source table")
	}
	section, _, _ = strings.Cut(section, "\n## ")
	count := 0
	for _, line := range strings.Split(section, "\n") {
		columns := strings.Split(line, "|")
		if len(columns) != 5 {
			continue
		}
		flag := strings.TrimSpace(columns[3])
		if flag != "true" && flag != "false" {
			continue
		}
		code := RefusalCode(strings.TrimSpace(columns[1]))
		r, err := NewRefusal(code)
		if err != nil || r.Type != "refusal" || r.Code != code || r.Retryable != (flag == "true") {
			t.Fatalf("code %s: %#v, %v; retryable should be %s", code, r, err, flag)
		}
		encoded, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		wire := mustDecode(t, string(encoded)).(map[string]any)
		if len(wire) != 3 || wire["type"] != "refusal" || wire["code"] != string(code) || wire["retryable"] != r.Retryable {
			t.Fatalf("wrong wire shape: %s", encoded)
		}
		count++
	}
	if count != 31 || count != len(refusalRetryable) {
		t.Fatalf("normative codes %d; implementation codes %d; want 31", count, len(refusalRetryable))
	}
	for _, code := range []RefusalCode{"", "unknown", "INVALID_JSON"} {
		if r, err := NewRefusal(code); r != nil || err == nil {
			t.Fatalf("unknown refusal code accepted: %#v, %v", r, err)
		}
	}
}
