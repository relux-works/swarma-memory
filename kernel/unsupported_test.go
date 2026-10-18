package kernel

import "testing"

// TestUnsupported proves all four interface methods return zero payloads and
// the exact non-retryable closed refusal; no evaluation success is fabricated.
func TestUnsupported(t *testing.T) {
	var k Kernel = Unsupported{}
	receipts, a := k.Admit(Context{}, nil)
	view, b := k.Recall(Context{}, Query{})
	explanation, c := k.Explain(Context{}, VersionRef{}, Bounds{})
	changes, d := k.Changes(Context{}, Cursor{}, Bounds{})
	if receipts.Receipt != nil || view != (View{}) || explanation != (Explanation{}) || changes != (ChangeSet{}) {
		t.Fatal("nonzero unsupported payload")
	}
	for _, r := range []*Refusal{a, b, c, d} {
		if r == nil || r.Type != "refusal" || r.Code != UnsupportedOperation || r.Retryable {
			t.Fatal(r)
		}
	}
}
