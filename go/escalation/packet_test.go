package escalation

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/relux-works/swarma-memory/go/kernel"
	"github.com/relux-works/swarma-memory/go/space"
)

func fixture(t *testing.T, id string) (map[string]any, []any) {
	t.Helper()
	b, e := os.ReadFile("../../spec/kernel/vectors/semantic/" + id + ".json")
	if e != nil {
		t.Fatal(e)
	}
	v, r := kernel.DecodeJSON(b)
	if r != nil {
		t.Fatal(r)
	}
	doc := object(v)
	s := object(doc["initial_state"])
	schemas, r := kernel.LoadSchemas(os.DirFS("../../spec/kernel/schemas"))
	if r != nil {
		t.Fatal(r)
	}
	count := 0
	state, r := kernel.NewState(s, schemas, func() (string, error) { count++; return strings.Repeat("0", 31) + string(rune('a'+count)), nil })
	if r != nil {
		t.Fatal(r)
	}
	for _, op := range array(doc["operations"]) {
		m := object(op)
		if m["op"] == "read" {
			continue
		}
		if _, r := state.Write(m); r != nil {
			t.Fatal(r)
		}
	}
	q := object(doc["query"])
	view, r := state.Read(q)
	if r != nil {
		t.Fatal(r)
	}
	return view, array(state.Snapshot()["records"])
}

// The existing test-profile ambiguity produces a reference-only packet without
// adding authority events to the documentary Git profile or changing the kernel.
func TestAmbiguousCurrentPacket(t *testing.T) {
	view, records := fixture(t, "S28")
	p := space.Policy{SpaceID: "space:test", Version: 1, Owners: []string{"owner"}}
	packet := New("reader", nil, nil)
	packet.Conflicts = FromView(view, Ref{ID: "schema:decision", Version: 1}, p, "sha256:"+strings.Repeat("0", 64), strings.Repeat("a", 40), records, false)
	packet.Normalize(false)
	if len(packet.Conflicts) != 1 || len(packet.Conflicts[0].Items) != 2 {
		t.Fatal("ambiguity missing")
	}
	for _, c := range packet.Conflicts {
		if c.Kind != "ambiguous_current" || c.Basis != "default_owners" {
			t.Fatal(c)
		}
	}
	if r := Validate(packet); r != nil {
		t.Fatal(r)
	}
	b, _ := json.Marshal(packet)
	for _, bad := range []string{"content", "excerpt", "retention_admission"} {
		if strings.Contains(string(b), `"`+bad+`"`) {
			t.Fatal("prose leaked")
		}
	}
	// Closed schemas reject planted content at every meaningful nesting boundary.
	var value map[string]any
	json.Unmarshal(b, &value)
	for _, target := range []map[string]any{value, object(value["dependent"]), object(array(value["conflicts"])[0]), object(array(object(array(value["conflicts"])[0])["items"])[0]), object(object(array(value["conflicts"])[0])["evidence"])} {
		target["content"] = "do this"
		if Validate(value) == nil {
			t.Fatal("content admitted")
		}
		delete(target, "content")
	}
}

// Keys depend on the exact reported ref set, not the order, duplicate refs,
// reporter, cursor or policy. Distinct routes share one report-wide key.
func TestReportedKeyAndRoutes(t *testing.T) {
	a, b := LocatedRef{"space:a", Ref{ID: "x", Version: 1}}, LocatedRef{"space:b", Ref{ID: "y", Version: 2}}
	// Fixed independent canonical-JSON/SHA256 oracle, not another formatter run.
	if Key("reported", []LocatedRef{b, a}) != "sha256:5ac81b3bba9440247fd0b0450ec8951c96eea3aae26c495d1a06cd53dcd4dd3f" || Key("incompatible", []LocatedRef{a, b}) == Key("reported", []LocatedRef{a, b}) {
		t.Fatal("canonical key or kind isolation changed")
	}
	if Key("reported", []LocatedRef{a, b}) != Key("reported", []LocatedRef{b, a, a}) || Key("reported", []LocatedRef{a}) == Key("reported", []LocatedRef{a, b}) {
		t.Fatal("key set semantics")
	}
	p := New("a", nil, nil)
	p.Conflicts = []Conflict{{Space: a.Space, Items: []Item{{Ref: a.Ref}}, Resolvers: []string{"one"}, Basis: "named"}, {Space: b.Space, Items: []Item{{Ref: b.Ref}}, Resolvers: []string{"two"}, Basis: "named"}}
	p.Normalize(true)
	if len(p.Conflicts) != 2 || p.Conflicts[0].Key != p.Conflicts[1].Key {
		t.Fatal(p)
	}
}
