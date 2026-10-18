package scan

import (
	"encoding/base64"
	"encoding/json"
	"math"
	"regexp"
	"sort"
	"strings"
)

// These are conservative format heuristics, not provider validity checks. All
// matched spans are used only for pointer redaction within the scan call.
var tokenRules = []struct {
	detector Detector
	pattern  *regexp.Regexp
}{
	{AWSAccessKey, regexp.MustCompile(`(?:AKIA|ASIA)[A-Z0-9]{16}`)},
	{GitHubToken, regexp.MustCompile(`(?:gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59})`)},
	{SlackToken, regexp.MustCompile(`(?:xox[baprs]-[A-Za-z0-9-]{20,256}|xapp-[A-Za-z0-9-]{20,256}|xwfp-[A-Za-z0-9-]{20,256})`)},
	{StripeKey, regexp.MustCompile(`(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{24,256}`)},
	{GoogleAPIKey, regexp.MustCompile(`AIza[A-Za-z0-9_-]{35}`)},
	{OpenAIKey, regexp.MustCompile(`sk-(?:[A-Za-z0-9]{48}|(?:proj|svcacct)-[A-Za-z0-9_-]{32,256})`)},
	{AnthropicKey, regexp.MustCompile(`sk-ant-(?:api|admin)[0-9]{2}-[A-Za-z0-9_-]{32,256}`)},
	{Bearer, regexp.MustCompile(`(?i)\bBearer[ \t]+[A-Za-z0-9._~+/-]+=*`)},
}

var (
	privateKeyPattern  = regexp.MustCompile(`(?i)-----BEGIN (?:[^\r\n]* )?PRIVATE KEY-----`)
	urlPasswordPattern = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://[^/@?#\s:]*:[^/@?#\s]+@`)
	jwtPattern         = regexp.MustCompile(`[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*`)
	entropyPattern     = regexp.MustCompile(`[A-Za-z0-9+/_=-]+`)
	uuidPattern        = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

type stringScan struct {
	detectors []Detector
	secrets   []string
}

func stringDetectors(text string, oversized, exemptEntropy bool) stringScan {
	var secrets []string
	found := make(map[Detector]bool)
	if oversized {
		found[StringSize] = true
	}
	for _, rule := range tokenRules {
		for _, loc := range rule.pattern.FindAllStringIndex(text, -1) {
			if bounded(text, loc) {
				found[rule.detector] = true
				match := text[loc[0]:loc[1]]
				secrets = append(secrets, match)
				if rule.detector == Bearer {
					secrets = append(secrets, strings.TrimSpace(match[len("Bearer"):]))
				}
			}
		}
	}
	for _, match := range privateKeyPattern.FindAllString(text, -1) {
		found[PrivateKey] = true
		secrets = append(secrets, match)
	}
	for _, match := range urlPasswordPattern.FindAllString(text, -1) {
		found[URLPassword] = true
		userinfo := match[strings.Index(match, "://")+3 : len(match)-1]
		password := userinfo[strings.IndexByte(userinfo, ':')+1:]
		secrets = append(secrets, match, password)
	}
	// Retry at the next segment when a dotted prefix precedes a JWT, rather
	// than consuming its header/payload as an unrelated three-part candidate.
	for start := 0; start < len(text); {
		loc := jwtPattern.FindStringIndex(text[start:])
		if loc == nil {
			break
		}
		loc[0] += start
		loc[1] += start
		candidate := text[loc[0]:loc[1]]
		if bounded(text, loc) && validJWT(candidate) {
			found[JWT] = true
			secrets = append(secrets, candidate)
		}
		start = loc[0] + strings.IndexByte(candidate, '.') + 1
	}
	if !exemptEntropy {
		for _, candidate := range entropyPattern.FindAllString(text, -1) {
			if len(candidate) < 32 || uuidPattern.MatchString(candidate) {
				continue
			}
			if hex(candidate, len(candidate)) {
				if entropy(candidate) >= 3.0 {
					found[EntropyHex] = true
					secrets = append(secrets, candidate)
				}
			} else if len(strings.TrimRight(candidate, "=")) >= 32 && base64Alphabet(candidate) && entropy(strings.TrimRight(candidate, "=")) >= 4.5 {
				found[EntropyBase64] = true
				secrets = append(secrets, candidate)
			}
		}
	}
	out := make([]Detector, 0, len(found))
	for detector := range found {
		out = append(out, detector)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return stringScan{detectors: out, secrets: secrets}
}

// Identifier boundaries reject truncated fixed-length tokens inside longer
// credentials. Punctuation such as quotes and slashes can surround a token.
func bounded(text string, loc []int) bool {
	return (loc[0] == 0 || !tokenByte(text[loc[0]-1])) && (loc[1] == len(text) || !tokenByte(text[loc[1]]))
}

func tokenByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("_-+=", rune(c))
}

func validJWT(text string) bool {
	parts := strings.Split(text, ".")
	if len(parts) != 3 {
		return false
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	var object map[string]any
	if json.Unmarshal(header, &object) != nil {
		return false
	}
	algorithm, ok := object["alg"].(string)
	if !ok || algorithm == "" {
		return false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	var claims map[string]any
	if err != nil || json.Unmarshal(payload, &claims) != nil || claims == nil {
		return false
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	return err == nil && (len(signature) > 0 || algorithm == "none")
}

func base64Alphabet(text string) bool {
	unpadded := strings.TrimRight(text, "=")
	if len(text)-len(unpadded) > 2 || strings.ContainsRune(unpadded, '=') {
		return false
	}
	for _, c := range unpadded {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("+/_-", c)) {
			return false
		}
	}
	return true
}

func hex(text string, size int) bool {
	if len(text) != size || size == 0 {
		return false
	}
	for _, c := range text {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

func entropy(text string) float64 {
	var counts [256]int
	for i := range text {
		counts[text[i]]++
	}
	var result float64
	// Fixed byte order avoids nondeterministic floating-point accumulation.
	for _, n := range counts {
		if n > 0 {
			p := float64(n) / float64(len(text))
			result -= p * math.Log2(p)
		}
	}
	return result
}

// Entropy exemptions require both an exact path and a complete value format.
// They never apply to keys, known-format detectors, arbitrary content fields, or
// strings that merely contain a digest/handle next to other text. Root body
// paths let callers scan a body independently (as in the corpus check).
func entropyExempt(text, path string, root any) bool {
	switch path {
	case "/output_digest", "/declassification/output_digest", "/body/declassification/output_digest":
		return lowerHex(text, 64)
	case "/locator", "/object", "/body/locator", "/body/object":
		return strings.HasPrefix(text, "sha256:") && lowerHex(strings.TrimPrefix(text, "sha256:"), 64)
	case "/authorized_snapshot_handle", "/receipt_handle", "/body/authorized_snapshot_handle", "/body/receipt_handle":
		return lowerHex(text, 32)
	case "/digest/value", "/body/digest/value":
		object, _ := root.(map[string]any)
		if strings.HasPrefix(path, "/body/") {
			object, _ = object["body"].(map[string]any)
		}
		digest, _ := object["digest"].(map[string]any)
		return digest["algorithm"] == "sha256-cjson-v1" && lowerHex(text, 64)
	}
	return false
}

func lowerHex(text string, size int) bool {
	return hex(text, size) && strings.ToLower(text) == text
}
