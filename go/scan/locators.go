package scan

import (
	"net/netip"
	"strconv"
	"strings"

	"github.com/relux-works/swarma-memory/go/kernel"
)

// ParseSessionLocator recognizes only the documented entropy-exempt session
// forms. Unknown forms may still be accepted by a caller, with ordinary scanning.
// In particular a Matrix room's server/port belongs to Session, not Message.
func ParseSessionLocator(text string) (runtime, session, message string, ok bool) {
	if strings.HasPrefix(text, "matrix:") {
		rest := strings.TrimPrefix(text, "matrix:")
		cut := strings.LastIndex(rest, ":$")
		if cut < 0 {
			return "", "", "", false
		}
		session, message = rest[:cut], rest[cut+1:]
		return "matrix", session, message, matrixRoom(session) && matrixEvent(message)
	}
	parts := strings.SplitN(text, ":", 3)
	if len(parts) != 3 || (parts[0] != "codex" && parts[0] != "claude-code") || !uuidPattern.MatchString(parts[1]) {
		return "", "", "", false
	}
	message = parts[2]
	id := strings.TrimPrefix(message, "message:")
	return parts[0], parts[1], message, uuidPattern.MatchString(id) || decimalIndex(strings.TrimPrefix(message, "index:"))
}

func decimalIndex(s string) bool {
	if s == "" || len(s) > 20 {
		return false
	}
	for i := range s {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	_, err := strconv.ParseUint(s, 10, 64)
	return err == nil
}

func matrixEvent(s string) bool { return len(s) == 44 && s[0] == '$' && urlIdentifier(s[1:]) }

func urlIdentifier(s string) bool {
	if s == "" {
		return false
	}
	for i := range s {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// This is a conservative ASCII subset of legacy !localpart:server room IDs.
// Other Matrix identifier forms receive ordinary scanning, not an exemption.
func matrixRoom(s string) bool {
	if len(s) > 255 || len(s) < 4 || s[0] != '!' {
		return false
	}
	cut := strings.IndexByte(s, ':')
	return cut > 1 && urlIdentifier(s[1:cut]) && matrixServer(s[cut+1:])
}

func matrixPort(s string) bool {
	if len(s) > 5 || !decimalIndex(s) {
		return false
	}
	n, _ := strconv.Atoi(s)
	return n >= 1 && n <= 65535
}

func matrixServer(s string) bool {
	if strings.HasPrefix(s, "[") {
		cut := strings.IndexByte(s, ']')
		if cut < 0 {
			return false
		}
		address, err := netip.ParseAddr(s[1:cut])
		if err != nil || !address.Is6() || address.Zone() != "" {
			return false
		}
		suffix := s[cut+1:]
		return suffix == "" || strings.HasPrefix(suffix, ":") && matrixPort(suffix[1:])
	}
	host, port, hasPort := strings.Cut(s, ":")
	if hasPort && !matrixPort(port) {
		return false
	}
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := range label {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func locatorAtom(text string) bool {
	return matrixEvent(text) || matrixRoom(text) || lowerHex(text, 40) || lowerHex(text, 64) ||
		strings.HasPrefix(text, "sha256:") && lowerHex(strings.TrimPrefix(text, "sha256:"), 64) || uuidPattern.MatchString(text)
}

// New locator exemptions are source-record roles, not names that arbitrary
// content can opt into. Existing digest/handle exemptions are kept separately.
func sourceLocatorExempt(text, path string, root any) bool {
	if path != "/body/object" && path != "/body/revision" && path != "/body/origin" {
		return false
	}
	record, _ := root.(map[string]any)
	envelope, _ := record["envelope"].(map[string]any)
	body, _ := record["body"].(map[string]any)
	if envelope["kind"] != "source" || body["source_kind"] != "artifact" {
		return false
	}
	if locatorAtom(text) {
		return true
	}
	if path == "/body/revision" {
		return strings.HasPrefix(text, "message:") && locatorAtom(strings.TrimPrefix(text, "message:")) ||
			strings.HasPrefix(text, "index:") && decimalIndex(strings.TrimPrefix(text, "index:"))
	}
	origin, ok := body["origin"].(string)
	if !ok {
		return false
	}
	decoded, refusal := kernel.DecodeJSON([]byte(origin))
	if refusal != nil {
		return false
	}
	parts, ok := decoded.(map[string]any)
	if !ok || len(parts) != 3 {
		return false
	}
	r, rok := parts["runtime"].(string)
	s, sok := parts["session"].(string)
	m, mok := parts["message"].(string)
	if !rok || !sok || !mok {
		return false
	}
	pr, ps, pm, valid := ParseSessionLocator(r + ":" + s + ":" + m)
	if !valid || pr != r || ps != s || pm != m {
		return false
	}
	canonical, refusal := kernel.CanonicalJSON(parts)
	if refusal != nil || string(canonical) != origin {
		return false
	}
	revision := m
	if !strings.HasPrefix(m, "message:") && !strings.HasPrefix(m, "index:") {
		if decimalIndex(m) {
			revision = "index:" + m
		} else {
			revision = "message:" + m
		}
	}
	return body["owner"] == "runtime:"+r && body["object"] == "session:"+s && body["revision"] == revision &&
		(path == "/body/origin" && text == origin || path == "/body/object" && text == "session:"+s)
}
