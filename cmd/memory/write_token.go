package main

import (
	"encoding/base64"
	"strings"

	"github.com/relux-works/swarma-memory/agentprofile"
	"github.com/relux-works/swarma-memory/kernel"
)

// Tokens contain only already disclosed read metadata. They are optimistic
// preconditions, never authorization capabilities or authenticated view handles.
func readWriteToken(spaceID, cursor string, ref any) any {
	if ref == nil {
		return nil
	}
	b, _ := kernel.CanonicalJSON(map[string]any{"space": spaceID, "cursor": cursor, "target": ref})
	return "write:1:" + base64.RawURLEncoding.EncodeToString(b)
}

func decodeWriteToken(raw string) (map[string]any, error) {
	if len(raw) > 2*inputLimit || !strings.HasPrefix(raw, "write:1:") {
		return nil, cliError{"usage", 2}
	}
	b, e := base64.RawURLEncoding.Strict().DecodeString(strings.TrimPrefix(raw, "write:1:"))
	if e != nil {
		return nil, cliError{"usage", 2}
	}
	v, f := kernel.DecodeJSON(b)
	t := agentprofile.Object(v)
	ref := agentprofile.Object(t["target"])
	spaceID, spaceOK := t["space"].(string)
	cursor, cursorOK := t["cursor"].(string)
	id, idOK := ref["id"].(string)
	n, versionOK := ref["version"].(int64)
	if f != nil || len(t) != 3 || len(ref) != 2 || !spaceOK || spaceID == "" || !cursorOK || len(cursor) != 40 && len(cursor) != 64 || !idOK || id == "" || !versionOK || n < 1 {
		return nil, cliError{"usage", 2}
	}
	for _, c := range cursor {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return nil, cliError{"usage", 2}
		}
	}
	return t, nil
}

// This selects input metadata within one opaque record ID. It does not decide
// sequence ambiguity, representation, disclosure or admission; the kernel does.
func latestWriteTarget(snapshot map[string]any, id string) (map[string]any, map[string]any, error) {
	target, e := findRecord(snapshot, id, 0)
	if e != nil {
		return nil, nil, e
	}
	expected := recordRef(target)
	var lastSequence int64
	for _, raw := range agentprofile.Array(snapshot["records"]) {
		r := agentprofile.Object(raw)
		env, body := agentprofile.Object(r["envelope"]), agentprofile.Object(r["body"])
		sequence, _ := agentprofile.Object(env["recorded"])["sequence"].(int64)
		if env["kind"] == "revision" && body["relation"] != "challenge" && agentprofile.Object(body["target"])["id"] == id && sequence > lastSequence {
			lastSequence = sequence
			if replacement := agentprofile.Object(body["replacement"]); replacement != nil {
				expected = replacement
			} else {
				expected = recordRef(r)
			}
		}
	}
	return target, expected, nil
}

func pinnedWriteTarget(snapshot map[string]any, spaceID string, a arguments) (map[string]any, map[string]any, error) {
	id := a.pos[1]
	var targetRef, expected map[string]any
	if raw, ok := a.flags["expected-token"]; ok {
		token, e := decodeWriteToken(raw)
		if e != nil {
			return nil, nil, e
		}
		targetRef = agentprofile.Object(token["target"])
		if token["space"] != spaceID || targetRef["id"] != id {
			return nil, nil, cliError{"version_conflict", 3}
		}
		_, expected, e = latestWriteTarget(snapshot, id)
		if e != nil {
			return nil, nil, cliError{"version_conflict", 3}
		}
	} else {
		n, e := numberFlag(a, "expected-version", 0, 1)
		if e != nil {
			return nil, nil, e
		}
		expected = agentprofile.Ref(defaultFlag(a, "expected-id", id), n)
		targetRef = expected
		if expected["id"] != id {
			revision, e := findRecord(snapshot, expected["id"].(string), n)
			body := agentprofile.Object(revision["body"])
			if e != nil || agentprofile.Object(revision["envelope"])["kind"] != "revision" || body["relation"] != "withdraw" || agentprofile.Object(body["target"])["id"] != id {
				return nil, nil, cliError{"version_conflict", 3}
			}
			targetRef = agentprofile.Object(body["target"])
		}
	}
	if _, ok := a.flags["version"]; ok {
		n, e := numberFlag(a, "version", 0, 1)
		if e != nil {
			return nil, nil, e
		}
		if n != targetRef["version"] {
			return nil, nil, cliError{"version_conflict", 3}
		}
	}
	target, e := findRecord(snapshot, id, targetRef["version"].(int64))
	if e != nil {
		return nil, nil, cliError{"version_conflict", 3}
	}
	return target, expected, nil
}

func checkWriteTarget(snapshot map[string]any, spaceID, cursor string, a arguments) error {
	target, expected, e := pinnedWriteTarget(snapshot, spaceID, a)
	if e != nil {
		return e
	}
	if raw, ok := a.flags["expected-token"]; ok {
		token, _ := decodeWriteToken(raw) // Validated above.
		if token["cursor"] != cursor {
			return cliError{"version_conflict", 3}
		}
	}
	latest, current, e := latestWriteTarget(snapshot, a.pos[1])
	if e != nil {
		return e
	}
	aRef, _ := kernel.CanonicalJSON(recordRef(target))
	bRef, _ := kernel.CanonicalJSON(recordRef(latest))
	aToken, _ := kernel.CanonicalJSON(expected)
	bToken, _ := kernel.CanonicalJSON(current)
	if string(aRef) != string(bRef) || string(aToken) != string(bToken) {
		return cliError{"version_conflict", 3}
	}
	return nil
}
