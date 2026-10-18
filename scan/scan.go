// Package scan checks canonical record trees for obvious secrets and size limits.
// It is an offline write refusal filter, not proof that a record contains no secrets.
package scan

import (
	"sort"
	"strconv"
	"strings"

	"github.com/relux-works/swarma-memory/kernel"
)

// Limits are inclusive space-policy caps. String length counts UTF-8 bytes,
// including object keys; total size counts kernel canonical JSON bytes. Zero is
// a real cap, not an unlimited/default value. Negative caps refuse the input.
type Limits struct {
	MaxCanonicalBytes int
	MaxStringBytes    int
	MaxArrayLength    int
}

// Detector identifies a refusal reason without including any record content.
type Detector string

const (
	InvalidLimits Detector = "invalid_limits"
	InvalidJSON   Detector = "invalid_json"
	CanonicalSize Detector = "canonical_size"
	StringSize    Detector = "string_size"
	ArraySize     Detector = "array_size"
	AWSAccessKey  Detector = "aws_access_key"
	GitHubToken   Detector = "github_token"
	SlackToken    Detector = "slack_token"
	StripeKey     Detector = "stripe_key"
	GoogleAPIKey  Detector = "google_api_key"
	OpenAIKey     Detector = "openai_key"
	AnthropicKey  Detector = "anthropic_key"
	JWT           Detector = "jwt"
	Bearer        Detector = "bearer"
	URLPassword   Detector = "url_password"
	PrivateKey    Detector = "private_key"
	EntropyHex    Detector = "entropy_hex"
	EntropyBase64 Detector = "entropy_base64"
)

// Finding never includes detected secrets in excerpts or pointers.
// Pointer is an RFC 6901 JSON Pointer. For a flagged object key, or descendants
// of one (including keys containing a secret detected elsewhere), it names the
// nearest safe ancestor instead and PointerRedacted is true.
// InKey distinguishes a key finding from a value/container finding. Excerpt is
// always fully redacted: surrounding text can itself contain another secret.
type Finding struct {
	Detector        Detector `json:"detector"`
	Pointer         string   `json:"pointer"`
	Excerpt         string   `json:"excerpt"`
	InKey           bool     `json:"in_key,omitempty"`
	PointerRedacted bool     `json:"pointer_redacted,omitempty"`
}

// Scan returns nil on success, otherwise sorted, typed findings. The input must
// be an acyclic tree in kernel.DecodeJSON's value types; kernel.Record is also
// accepted at the root. It does not mutate or retain the input. Every string and
// object key is checked, even after size findings. Unsupported Go values fail
// closed with InvalidJSON; callers should still perform schema admission first.
func Scan(value any, limits Limits) []Finding {
	if limits.MaxCanonicalBytes < 0 || limits.MaxStringBytes < 0 || limits.MaxArrayLength < 0 {
		return []Finding{finding(InvalidLimits, "", false, false)}
	}
	if record, ok := value.(kernel.Record); ok {
		value = map[string]any(record)
	}
	canonical, refusal := kernel.CanonicalJSON(value)
	if refusal != nil {
		return []Finding{finding(InvalidJSON, "", false, false)}
	}
	type pendingFinding struct {
		detector Detector
		path     []string
		inKey    bool
	}
	var pending []pendingFinding
	if len(canonical) > limits.MaxCanonicalBytes {
		pending = append(pending, pendingFinding{detector: CanonicalSize})
	}
	// Keep matched spans only within this call. A separate pointer pass also
	// protects secrets embedded in otherwise nonmatching ancestor/sibling keys.
	secrets := make(map[string]bool)
	unsafeKeys := make(map[string]bool)
	scanString := func(text string, path []string, inKey, exempt bool) {
		result := stringDetectors(text, len(text) > limits.MaxStringBytes, exempt)
		if inKey && len(result.detectors) > 0 {
			unsafeKeys[text] = true
		}
		for _, detector := range result.detectors {
			pending = append(pending, pendingFinding{detector: detector, path: path, inKey: inKey})
		}
		for _, secret := range result.secrets {
			secrets[secret] = true
		}
	}
	root := value
	var walk func(any, string, []string)
	walk = func(value any, path string, segments []string) {
		switch value := value.(type) {
		case string:
			scanString(value, segments, false, entropyExempt(value, path, root))
		case []any:
			if len(value) > limits.MaxArrayLength {
				pending = append(pending, pendingFinding{detector: ArraySize, path: segments})
			}
			for i, child := range value {
				segment := strconv.Itoa(i)
				walk(child, path+"/"+segment, childPath(segments, segment))
			}
		case map[string]any:
			keys := make([]string, 0, len(value))
			for key := range value {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				next := childPath(segments, key)
				scanString(key, next, true, false)
				walk(value[key], path+"/"+escapePointer(key), next)
			}
		}
	}
	walk(value, "", nil)
	var findings []Finding
	for _, p := range pending {
		pointer, redacted := safePointer(p.path, secrets, unsafeKeys)
		findings = append(findings, finding(p.detector, pointer, p.inKey, redacted))
	}
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Pointer != findings[j].Pointer {
			return findings[i].Pointer < findings[j].Pointer
		}
		if findings[i].Detector != findings[j].Detector {
			return findings[i].Detector < findings[j].Detector
		}
		return findings[i].InKey && !findings[j].InKey
	})
	return findings
}

func finding(detector Detector, pointer string, inKey, redacted bool) Finding {
	return Finding{Detector: detector, Pointer: pointer, Excerpt: "[REDACTED]", InKey: inKey, PointerRedacted: redacted}
}

func escapePointer(segment string) string {
	return strings.ReplaceAll(strings.ReplaceAll(segment, "~", "~0"), "/", "~1")
}

func childPath(parent []string, segment string) []string {
	child := make([]string, len(parent)+1)
	copy(child, parent)
	child[len(parent)] = segment
	return child
}

func safePointer(path []string, secrets, unsafeKeys map[string]bool) (string, bool) {
	pointer := ""
	for _, segment := range path {
		if unsafeKeys[segment] {
			return pointer, true
		}
		next := pointer + "/" + escapePointer(segment)
		for secret := range secrets {
			if strings.Contains(segment, secret) || strings.Contains(next, secret) {
				return pointer, true
			}
		}
		pointer = next
	}
	return pointer, false
}
