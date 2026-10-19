package kernel

import (
	"bytes"
	"math"
	"os"
	"reflect"
	"testing"
)

func mustDecode(t *testing.T, text string) any {
	t.Helper()
	value, r := DecodeJSON([]byte(text))
	if r != nil {
		t.Fatalf("decode fixture: %v", r)
	}
	return value
}

func requireRefusal(t *testing.T, r *Refusal, code RefusalCode) {
	t.Helper()
	if r == nil || r.Type != "refusal" || r.Code != code || r.Retryable {
		t.Fatalf("refusal = %#v; want non-retryable %s", r, code)
	}
}

// TestStrictJSON proves each listed encoding/number/duplicate failure returns invalid_json without a partial tree, beside valid input.
func TestStrictJSON(t *testing.T) {
	for _, test := range []struct{ name, bad, good string }{
		{"invalid UTF-8", "\"\xff\"", `"�"`},
		{"UTF-8 surrogate", "\"\xed\xa0\x80\"", `"\ud800\udc00"`},
		{"duplicate root key", `{"a":1,"a":2}`, `{"a":1,"b":2}`},
		{"duplicate nested key", `{"a":[{"b":null,"b":false}]}`, `{"a":[{"b":null,"c":false}]}`},
		{"escaped duplicate", `{"a":1,"\u0061":2}`, `{"a":1,"A":2}`},
		{"non-BMP duplicate", `{"😀":1,"\ud83d\ude00":2}`, `{"😀":1,"😁":2}`},
		{"fraction", `1.0`, `1`},
		{"negative zero fraction", `-0.0`, `-0`},
		{"exponent", `1e3`, `1000`},
		{"uppercase exponent", `1E+3`, `1000`},
		{"nested fraction", `{"a":[1.0]}`, `{"a":[1]}`},
		{"NaN", `NaN`, `null`},
		{"infinity", `Infinity`, `0`},
		{"negative infinity", `-Infinity`, `-1`},
		{"upper range", `9007199254740992`, `9007199254740991`},
		{"lower range", `-9007199254740992`, `-9007199254740991`},
		{"int64 overflow", `9223372036854775808`, `9007199254740991`},
		{"int64 underflow", `-9223372036854775809`, `-9007199254740991`},
		{"high surrogate", `"\ud800"`, `"\ud800\udc00"`},
		{"low surrogate", `"\udfff"`, `"\udbff\udfff"`},
		{"wrong surrogate partner", `"\ud800\u0061"`, `"\u0061"`},
		{"reversed surrogate pair", `"\udc00\ud800"`, `"\ud800\udc00"`},
		{"separated surrogate pair", `"\ud800x\udc00"`, `"\ud800\udc00x"`},
		{"surrogate key", `{"\ud800":1}`, `{"\ud800\udc00":1}`},
		{"trailing value", `{} []`, "{} \n\t"},
		{"trailing garbage", `true!`, `true`},
		{"empty input", ``, `null`},
		{"leading zero", `01`, `0`},
		{"leading plus", `+1`, `1`},
		{"incomplete array", `[1`, `[1]`},
		{"incomplete string", `"hello`, `"hello"`},
		{"unknown escape", `"\x01"`, `"\u0001"`},
		{"byte order mark", "\xef\xbb\xbfnull", `null`},
	} {
		t.Run(test.name, func(t *testing.T) {
			value, r := DecodeJSON([]byte(test.bad))
			requireRefusal(t, r, InvalidJSON)
			if value != nil {
				t.Fatal("refused input returned a partial tree")
			}
			if _, r := DecodeJSON([]byte(test.good)); r != nil {
				t.Fatalf("valid control refused: %v", r)
			}
		})
	}
}

// TestCanonicalJSON proves scalar-order keys, exact escapes/integers and ordered nesting match independently specified bytes.
func TestCanonicalJSON(t *testing.T) {
	for _, test := range []struct{ name, input, want string }{
		{"key order", `{"z":0,"a":1}`, `{"a":1,"z":0}`},
		{"key order before escaping", `{"a":0,"\n":1,"\"":2,"\\":3}`, `{"\n":1,"\"":2,"\\":3,"a":0}`},
		{"scalar rather than UTF-16 order", `{"𐀀":1,"":2}`, `{"":2,"𐀀":1}`},
		{"non-ASCII", `{"é":"Русский 😀"}`, `{"é":"Русский 😀"}`},
		{"no normalization", `{"é":1,"e\u0301":2}`, "{\"e\u0301\":2,\"é\":1}"},
		{"no case folding", `{"a":1,"A":2}`, `{"A":2,"a":1}`},
		{"short escapes", `"\u0022\u005c\u0008\u000c\u000a\u000d\u0009"`, `"\"\\\b\f\n\r\t"`},
		{"lowercase hex", `"\u0000\u000B\u001A\u001F"`, `"\u0000\u000b\u001a\u001f"`},
		{"no HTML or line-separator escapes", `"<>&/\u2028\u2029\u007f"`, "\"<>&/\u2028\u2029\x7f\""},
		{"all controls", `"\u0000\u0001\u0002\u0003\u0004\u0005\u0006\u0007\b\t\n\u000b\f\r\u000e\u000f\u0010\u0011\u0012\u0013\u0014\u0015\u0016\u0017\u0018\u0019\u001a\u001b\u001c\u001d\u001e\u001f"`, `"\u0000\u0001\u0002\u0003\u0004\u0005\u0006\u0007\b\t\n\u000b\f\r\u000e\u000f\u0010\u0011\u0012\u0013\u0014\u0015\u0016\u0017\u0018\u0019\u001a\u001b\u001c\u001d\u001e\u001f"`},
		{"nesting and array order", " {\"z\":[3,2,{\"b\":true,\"a\":null}],\"a\":[]} ", `{"a":[],"z":[3,2,{"a":null,"b":true}]}`},
		{"range and negative zero", `[-9007199254740991,9007199254740991,-0,0]`, `[-9007199254740991,9007199254740991,0,0]`},
		{"escaped surrogate pair", `"\ud83d\ude00"`, `"😀"`},
		{"literal escaped surrogate text", `"\\ud800"`, `"\\ud800"`},
	} {
		t.Run(test.name, func(t *testing.T) {
			value := mustDecode(t, test.input)
			output, r := CanonicalJSON(value)
			if r != nil || string(output) != test.want {
				t.Fatalf("canonical = %q, %v; want %q", output, r, test.want)
			}
			decoded, r := DecodeJSON(output)
			if r != nil || !reflect.DeepEqual(value, decoded) {
				t.Fatalf("round trip changed tree: %v", r)
			}
		})
	}
}

// TestCanonicalRefusals proves unsupported Go values and invalid strings/integers cannot produce partial canonical bytes or digests.
func TestCanonicalRefusals(t *testing.T) {
	for _, value := range []any{
		float64(1), math.NaN(), math.Inf(1), int(1), uint64(1),
		maxJSONInteger + 1, -maxJSONInteger - 1, string([]byte{0xff}),
		map[string]any{string([]byte{0xff}): nil},
		[]any{int64(1), float64(2)}, map[string]any{"a": true, "z": float64(1)},
	} {
		output, r := CanonicalJSON(value)
		requireRefusal(t, r, InvalidJSON)
		if output != nil {
			t.Fatal("refusal returned partial bytes")
		}
		digest, r := DigestJSON(value)
		requireRefusal(t, r, InvalidJSON)
		if digest != "" {
			t.Fatal("refusal returned a digest")
		}
	}
	if output, r := CanonicalJSON(int64(1)); r != nil || string(output) != "1" {
		t.Fatalf("valid integer refused: %q, %v", output, r)
	}
}

// TestP05Digest proves the programmatically located released assertion body matches the package's Python-built pin; a one-byte copy mutation differs.
func TestP05Digest(t *testing.T) {
	data, err := os.ReadFile("../../spec/kernel/vectors/semantic/P05.json")
	if err != nil {
		t.Fatal(err)
	}
	vector := mustDecode(t, string(data)).(map[string]any)
	state := vector["initial_state"].(map[string]any)
	policy := state["policy"].(map[string]any)
	decisions := policy["declassification_decisions"].([]any)
	const expected = "5de83fb8e3155c49b882fb716b571a54038bee18f06cc1989900cb49b16c2a3b"
	var body map[string]any
	for _, decision := range decisions {
		pins := decision.(map[string]any)["pins"].(map[string]any)
		if pins["output_digest"] != expected {
			continue
		}
		for _, operation := range vector["operations"].([]any) {
			op := operation.(map[string]any)
			if op["op"] != "declassify" {
				continue
			}
			output := op["output"].(map[string]any)
			if reflect.DeepEqual(output["envelope"].(map[string]any)["schema"], pins["output_schema"]) {
				body = output["body"].(map[string]any)
				break
			}
		}
	}
	if body == nil {
		t.Fatal("no pinned release assertion body found")
	}
	digest, r := DigestJSON(body)
	if r != nil || digest != expected {
		t.Fatalf("P05 digest = %s, %v; want %s", digest, r, expected)
	}
	canonical, _ := CanonicalJSON(body)
	copy := mustDecode(t, string(canonical)).(map[string]any)
	field := copy["content"].([]any)[0].(map[string]any)
	text := []byte(field["value"].(string))
	if len(text) == 0 || text[0] >= 0x80 {
		t.Fatal("mutation control needs a nonempty ASCII-leading value")
	}
	text[0] ^= 1
	field["value"] = string(text)
	mutated, r := CanonicalJSON(copy)
	if r != nil || len(mutated) != len(canonical) {
		t.Fatalf("mutation changed encoding length: %v", r)
	}
	changes := 0
	for i := range canonical {
		if canonical[i] != mutated[i] {
			changes++
		}
	}
	if changes != 1 {
		t.Fatalf("mutation changed %d canonical bytes; want 1", changes)
	}
	mutatedDigest, r := DigestJSON(copy)
	if r != nil || mutatedDigest == expected {
		t.Fatalf("changed body failed to change digest: %s, %v", mutatedDigest, r)
	}
	unchanged, _ := CanonicalJSON(body)
	if !bytes.Equal(canonical, unchanged) {
		t.Fatal("control mutated the original body")
	}
	t.Logf("P05 pin %s; one-byte mutation %s", digest, mutatedDigest)
}
