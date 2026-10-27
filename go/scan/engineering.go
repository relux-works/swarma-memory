package scan

import (
	"regexp"
	"strings"
)

var engineeringTaskID = regexp.MustCompile(`^TASK-[0-9]{6}-[a-z0-9]{6}$`)

// A complete 18-byte task-ID slash segment is a token boundary in values. It
// cannot supply the missing entropy/length that joins neighbouring short prose
// into a false positive. Preserve all other slash-joined runs, so base64 secrets
// containing slashes are not generally split into harmless short pieces. Check
// individual remaining segments too, preventing a long low-entropy neighbour
// from diluting an intact secret. If any remaining run is at least 32 bytes,
// retain the original candidate too: removing the task ID must not lower the
// entropy of a long possible secret below the threshold. Object keys stay strict.
func entropyCandidates(text string, inKey bool) []string {
	var out []string
	for _, candidate := range entropyPattern.FindAllString(text, -1) {
		if inKey || !strings.Contains(candidate, "/") {
			out = append(out, candidate)
			continue
		}
		parts := strings.Split(candidate, "/")
		hasID := false
		for _, part := range parts {
			hasID = hasID || engineeringTaskID.MatchString(part)
		}
		if !hasID {
			out = append(out, candidate)
			continue
		}
		var run []string
		retainOriginal := false
		flush := func() {
			if len(run) == 0 {
				return
			}
			joined := strings.Join(run, "/")
			retainOriginal = retainOriginal || len(joined) >= 32
			out = append(out, joined)
			if len(run) > 1 {
				out = append(out, run...)
			}
			run = nil
		}
		for _, part := range parts {
			if engineeringTaskID.MatchString(part) {
				flush()
			} else {
				run = append(run, part)
			}
		}
		flush()
		if retainOriginal {
			out = append(out, candidate)
		}
	}
	return out
}
