package kernel

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

const maxJSONInteger int64 = 9007199254740991

// DecodeJSON implements K-JSON-1. Trees contain only nil, bool, string, int64,
// []any and map[string]any; a refusal never returns a partial tree.
func DecodeJSON(input []byte) (any, *Refusal) {
	if !utf8.Valid(input) || !validSurrogates(input) || !json.Valid(input) {
		return nil, refusal(InvalidJSON)
	}
	d := json.NewDecoder(bytes.NewReader(input))
	d.UseNumber()
	value, ok := decodeJSONValue(d)
	if !ok {
		return nil, refusal(InvalidJSON)
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, refusal(InvalidJSON)
	}
	return value, nil
}

func decodeJSONValue(d *json.Decoder) (any, bool) {
	tok, err := d.Token()
	if err != nil {
		return nil, false
	}
	switch tok := tok.(type) {
	case json.Delim:
		switch tok {
		case '{':
			object := make(map[string]any)
			for d.More() {
				key, err := d.Token()
				name, ok := key.(string)
				if err != nil || !ok {
					return nil, false
				}
				if _, duplicate := object[name]; duplicate {
					return nil, false
				}
				value, ok := decodeJSONValue(d)
				if !ok {
					return nil, false
				}
				object[name] = value
			}
			end, err := d.Token()
			return object, err == nil && end == json.Delim('}')
		case '[':
			array := make([]any, 0)
			for d.More() {
				value, ok := decodeJSONValue(d)
				if !ok {
					return nil, false
				}
				array = append(array, value)
			}
			end, err := d.Token()
			return array, err == nil && end == json.Delim(']')
		}
		return nil, false
	case json.Number:
		text := string(tok)
		if strings.ContainsAny(text, ".eE") {
			return nil, false
		}
		n, err := strconv.ParseInt(text, 10, 64)
		return n, err == nil && n >= -maxJSONInteger && n <= maxJSONInteger
	default:
		return tok, true
	}
}

// encoding/json replaces unpaired surrogate escapes, so reject them before decoding.
// JSON syntax itself (including all other escape rules) is checked by json.Valid.
func validSurrogates(input []byte) bool {
	inString := false
	for i := 0; i < len(input); i++ {
		if input[i] == '"' {
			inString = !inString
			continue
		}
		if !inString || input[i] != '\\' {
			continue
		}
		i++
		if i >= len(input) {
			return false
		}
		if input[i] != 'u' {
			continue
		}
		if i+4 >= len(input) {
			return false
		}
		n, err := strconv.ParseUint(string(input[i+1:i+5]), 16, 16)
		if err != nil {
			return false
		}
		i += 4
		if n >= 0xDC00 && n <= 0xDFFF {
			return false
		}
		if n >= 0xD800 && n <= 0xDBFF {
			if i+6 >= len(input) || input[i+1] != '\\' || input[i+2] != 'u' {
				return false
			}
			low, err := strconv.ParseUint(string(input[i+3:i+7]), 16, 16)
			if err != nil || low < 0xDC00 || low > 0xDFFF {
				return false
			}
			i += 6
		}
	}
	return true
}

// CanonicalJSON implements K-JSON-2 for an acyclic tree in DecodeJSON's types.
// Other Go types, invalid UTF-8 and out-of-range integers are refused, never coerced.
func CanonicalJSON(value any) ([]byte, *Refusal) {
	output, ok := appendCanonical(nil, value)
	if !ok {
		return nil, refusal(InvalidJSON)
	}
	return output, nil
}

func appendCanonical(output []byte, value any) ([]byte, bool) {
	switch value := value.(type) {
	case nil:
		return append(output, "null"...), true
	case bool:
		return strconv.AppendBool(output, value), true
	case int64:
		if value < -maxJSONInteger || value > maxJSONInteger {
			return nil, false
		}
		return strconv.AppendInt(output, value, 10), true
	case string:
		return appendJSONString(output, value)
	case []any:
		output = append(output, '[')
		for i, child := range value {
			if i > 0 {
				output = append(output, ',')
			}
			var ok bool
			output, ok = appendCanonical(output, child)
			if !ok {
				return nil, false
			}
		}
		return append(output, ']'), true
	case map[string]any:
		keys := make([]string, 0, len(value))
		for key := range value {
			keys = append(keys, key)
		}
		// Valid UTF-8 byte order equals Unicode scalar-value order.
		sort.Strings(keys)
		output = append(output, '{')
		for i, key := range keys {
			if i > 0 {
				output = append(output, ',')
			}
			var ok bool
			output, ok = appendJSONString(output, key)
			if !ok {
				return nil, false
			}
			output = append(output, ':')
			output, ok = appendCanonical(output, value[key])
			if !ok {
				return nil, false
			}
		}
		return append(output, '}'), true
	default:
		return nil, false
	}
}

func appendJSONString(output []byte, text string) ([]byte, bool) {
	if !utf8.ValidString(text) {
		return nil, false
	}
	const digits = "0123456789abcdef"
	output = append(output, '"')
	for _, c := range text {
		switch c {
		case '"', '\\':
			output = append(output, '\\', byte(c))
		case '\b':
			output = append(output, '\\', 'b')
		case '\f':
			output = append(output, '\\', 'f')
		case '\n':
			output = append(output, '\\', 'n')
		case '\r':
			output = append(output, '\\', 'r')
		case '\t':
			output = append(output, '\\', 't')
		default:
			if c < 0x20 {
				output = append(output, '\\', 'u', '0', '0', digits[c>>4], digits[c&15])
			} else {
				output = utf8.AppendRune(output, c)
			}
		}
	}
	return append(output, '"'), true
}

// DigestJSON returns the lowercase sha256-cjson-v1 digest of a decoded tree.
func DigestJSON(value any) (string, *Refusal) {
	canonical, r := CanonicalJSON(value)
	if r != nil {
		return "", r
	}
	framed := append([]byte("bounded-evidence:cjson-v1\x00"), canonical...)
	digest := sha256.Sum256(framed)
	return hex.EncodeToString(digest[:]), nil
}

func equalJSON(a, b any) bool {
	switch a := a.(type) {
	case nil:
		return b == nil
	case bool:
		v, ok := b.(bool)
		return ok && a == v
	case string:
		v, ok := b.(string)
		return ok && a == v
	case int64:
		v, ok := b.(int64)
		return ok && a == v
	case []any:
		v, ok := b.([]any)
		if !ok || len(a) != len(v) {
			return false
		}
		for i := range a {
			if !equalJSON(a[i], v[i]) {
				return false
			}
		}
		return true
	case map[string]any:
		v, ok := b.(map[string]any)
		if !ok || len(a) != len(v) {
			return false
		}
		for key, value := range a {
			other, exists := v[key]
			if !exists || !equalJSON(value, other) {
				return false
			}
		}
		return true
	default:
		return false
	}
}
