package main

import (
	"reflect"
	"strings"
	"testing"

	"github.com/relux-works/swarma-memory/go/agentprofile"
)

// Plain replacement preserves a slash-joined task-ID compound without source
// flags. Real base64 and named secrets beside it still produce their intended
// redacted refusal and leave the complete write state unchanged.
func TestWriteEngineeringCompounds(t *testing.T) {
	h := newCLI(t)
	id := "TASK-123456-ghijkl"
	compound := "scan_refused3/" + id
	h.add(h.owner, "record:engineering", "Initial synthetic observation")
	h.invoke(h.owner, 0, "revise", "record:engineering", "--relation", "replace", "--expected-version", "1", "--idempotency-key", "engineering-2", "--content", compound)
	content := func(version int64) any {
		return agentprofile.Object(h.stored(h.owner, "space:test", "record:engineering", version)["body"])["content"]
	}
	want := func(text string) any { return []any{map[string]any{"field": "value", "value": text}} }
	if !reflect.DeepEqual(content(2), want(compound)) {
		t.Fatal("compound was rewritten")
	}
	secret := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"
	named := "gh" + "p_" + strings.Repeat("aB2cD3", 6)
	for i, row := range []struct{ value, detector string }{
		{secret, "entropy_base64"}, {"word/" + secret, "entropy_base64"},
		{compound + " " + secret, "entropy_base64"}, {compound + "/" + secret, "entropy_base64"},
		{secret + "/" + id, "entropy_base64"}, {compound + " " + named, "github_token"},
	} {
		before := h.writeState(h.owner)
		m, out, stderr := h.input(h.owner, "", 3, "revise", "record:engineering", "--relation", "replace", "--expected-version", "2", "--idempotency-key", "engineering-refusal-"+strconv64(int64(i)), "--content", row.value)
		found := false
		for _, f := range agentprofile.Array(agentprofile.Object(m["data"])["findings"]) {
			found = found || agentprofile.Object(f)["detector"] == row.detector
		}
		if errorCodeOf(m) != "scan_refused" || !found || strings.Contains(string(out), secret) || strings.Contains(string(stderr), secret) || strings.Contains(string(out), named) || strings.Contains(string(stderr), named) {
			t.Fatal("wrong or unsafe engineering refusal", i)
		}
		h.unchanged(h.owner, before)
	}
	pseudo := "v0.0.0-20260102030405-123456abcdef"
	h.invoke(h.owner, 0, "revise", "record:engineering", "--relation", "replace", "--expected-version", "2", "--idempotency-key", "engineering-3", "--content", pseudo)
	if !reflect.DeepEqual(content(3), want(pseudo)) {
		t.Fatal("valid pseudoversion control changed")
	}
}
