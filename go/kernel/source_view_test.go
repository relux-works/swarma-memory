package kernel

import "testing"

// The same effective availability drives source payloads and evaluation. A
// hidden revision must affect neither public bytes nor source resolution; a
// private-reader control sees the latest admitted state, independent of order.
func TestSourceAvailabilityVisibility(t *testing.T) {
	snapshot, q, operations := readFixture(t, "S44")
	revision := obj(operations[1])
	for _, availability := range []string{"unavailable", "erased"} {
		candidate := copyJSON(snapshot).(map[string]any)
		op := copyJSON(revision).(map[string]any)
		obj(obj(op["context"])["retention_context"])["audience"] = "aud:private"
		proposal := op["revision"]
		body(proposal)["availability"] = availability
		obj(env(proposal)["disclosure"])["audiences"] = []any{"aud:private"}
		s := stateForTest(t, candidate)
		before := readSuccess(t, s, obj(obj(operations[0])["query"]))
		if _, r := s.Write(op); r != nil {
			t.Fatal(r)
		}
		public := copyJSON(q).(map[string]any)
		public["kind"] = "recall"
		public["since"] = nil
		after := readSuccess(t, s, public)
		if !equalJSON(comparableView(before), comparableView(after)) {
			t.Fatal("hidden availability changed public view")
		}
		private := copyJSON(public).(map[string]any)
		private["audience"] = "aud:private"
		entry := obj(arr(readSuccess(t, s, private)["sources"])[0])
		if entry["availability"] != availability {
			t.Fatal("private reader missed revision", entry)
		}
		if availability == "erased" && obj(entry["excerpt"])["text"] != nil {
			t.Fatal("erased text leaked", entry)
		}
	}
}

// Table ordering is by numeric version (1,2,10), even when stored records and
// citation refs arrive in lexical JSON order; each exact ref appears only once.
func TestSourceTableNumericOrder(t *testing.T) {
	snapshot, q, _ := readFixture(t, "S43")
	records := arr(snapshot["records"])
	source := records[2]
	for _, version := range []int64{10, 2} {
		extra := copyJSON(source)
		env(extra)["version"] = version
		obj(env(extra)["recorded"])["sequence"] = int64(len(records) + 1)
		records = append(records, extra)
		for _, j := range records {
			if env(j)["kind"] == "justification" {
				body(j)["premises"] = append(arr(body(j)["premises"]), map[string]any{"kind": "source", "source": ref(extra)})
			}
		}
		fact := copyJSON(arr(obj(snapshot["policy"])["lineage_facts"])[0]).(map[string]any)
		fact["output"] = ref(extra)
		obj(snapshot["policy"])["lineage_facts"] = append(arr(obj(snapshot["policy"])["lineage_facts"]), fact)
	}
	snapshot["records"] = records
	// Premise arrays are sets in admitted records, sorted in canonical JSON order.
	for _, r := range records {
		if env(r)["kind"] == "justification" {
			body(r)["premises"] = set(arr(body(r)["premises"]))
		}
	}
	entries := arr(readSuccess(t, stateForTest(t, snapshot), q)["sources"])
	if len(entries) != 3 {
		t.Fatal("source closure or deduplication failed", entries)
	}
	for i, v := range []int64{1, 2, 10} {
		if obj(obj(entries[i])["ref"])["version"] != v {
			t.Fatal("non-numeric source order", entries)
		}
	}
}

// Erasing a source changes fresh historical reads, but the protected capture is
// detached and remains byte-identical; caller edits cannot rewrite it either.
func TestCapturedSourcesStayFrozen(t *testing.T) {
	snapshot, q, operations := readFixture(t, "S45")
	s := stateForTest(t, snapshot)
	frozen, r := s.Capture(0, obj(obj(operations[0])["query"]))
	if r != nil {
		t.Fatal(r)
	}
	original := copyJSON(frozen)
	if _, r = s.Write(obj(operations[1])); r != nil {
		t.Fatal(r)
	}
	if !equalJSON(s.Captured(0), original) {
		t.Fatal("erasure rewrote capture")
	}
	obj(arr(frozen["sources"])[0])["origin"] = "caller mutation"
	if !equalJSON(s.Captured(0), original) {
		t.Fatal("caller rewrote capture")
	}
	entry := obj(arr(readSuccess(t, s, q)["sources"])[0])
	if entry["availability"] != "erased" || obj(entry["excerpt"])["state"] != "erased" {
		t.Fatal("fresh read kept erased bytes", entry)
	}
}

// Both SourceView variants are closed and require every declared field. Text
// cannot hide in erased/none excerpts, and protected bindings never pass schema.
func TestSourceViewClosedVariants(t *testing.T) {
	schemas := packageSchemas(t)
	for _, id := range []string{"S43", "S52"} {
		snapshot, q, _ := readFixture(t, id)
		view := readSuccess(t, stateForTest(t, snapshot), q)
		for name := range obj(arr(view["sources"])[0]) {
			candidate := copyJSON(view).(map[string]any)
			delete(obj(arr(candidate["sources"])[0]), name)
			if schemas.Validate(candidate, packageSchema+"view") == nil {
				t.Fatal("missing source field accepted", id, name)
			}
		}
		for _, name := range []string{"retention_admission", "recorded", "lineage", "disclosure", "unknown"} {
			candidate := copyJSON(view).(map[string]any)
			obj(arr(candidate["sources"])[0])[name] = nil
			if schemas.Validate(candidate, packageSchema+"view") == nil {
				t.Fatal("unknown/protected field accepted", id, name)
			}
		}
		candidate := copyJSON(view).(map[string]any)
		obj(arr(candidate["sources"])[0])["excerpt"] = map[string]any{"state": "none", "text": "forbidden"}
		if schemas.Validate(candidate, packageSchema+"view") == nil {
			t.Fatal("none excerpt carried text", id)
		}
		if id == "S52" {
			for _, name := range []string{"object", "revision", "digest", "origin"} {
				candidate := copyJSON(view).(map[string]any)
				obj(arr(candidate["sources"])[0])[name] = "forbidden"
				if schemas.Validate(candidate, packageSchema+"view") == nil {
					t.Fatal("erased field accepted", name)
				}
			}
		}
	}
}

// Legacy bindings retain their stored hash locator, null digest and original
// message spelling; an empty retained excerpt is present, not absent.
func TestLegacySourceFieldsAndEmptyExcerpt(t *testing.T) {
	snapshot, q, _ := readFixture(t, "S43")
	source := arr(snapshot["records"])[2]
	body(source)["object"] = "sha256:legacy"
	body(source)["revision"] = "message-id-as-stored"
	body(source)["digest"] = nil
	body(source)["origin"] = "{\"runtime\":\"legacy\",\"session\":\"s\",\"message\":\"m\"}"
	body(source)["excerpt"] = ""
	entry := obj(arr(readSuccess(t, stateForTest(t, snapshot), q)["sources"])[0])
	for _, name := range []string{"object", "revision", "digest", "origin"} {
		if !equalJSON(entry[name], body(source)[name]) {
			t.Fatal("legacy field rewritten", name, entry)
		}
	}
	if !equalJSON(entry["excerpt"], map[string]any{"state": "present", "text": ""}) {
		t.Fatal("empty excerpt lost", entry)
	}
}
