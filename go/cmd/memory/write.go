package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/relux-works/swarma-memory/go/agentprofile"
	"github.com/relux-works/swarma-memory/go/kernel"
	"github.com/relux-works/swarma-memory/go/scan"
	"github.com/relux-works/swarma-memory/go/space"
)

const writeRetries = 2
const inputLimit = 1000000

type writeData struct {
	ID      string         `json:"id"`
	Version int64          `json:"version"`
	Commit  string         `json:"commit"`
	Cursor  string         `json:"cursor"`
	Receipt map[string]any `json:"receipt"`
}

type writeInput struct {
	a         arguments
	body      map[string]any
	sources   []any
	text      string
	session   map[string]any
	validFrom string
}

func defaultFlag(a arguments, name, fallback string) string {
	if value, ok := a.flags[name]; ok {
		return value
	}
	return fallback
}
func numberFlag(a arguments, name string, fallback int64, minimum int64) (int64, error) {
	if raw, ok := a.flags[name]; ok {
		n, e := strconv.ParseInt(raw, 10, 64)
		if e != nil || n < minimum || n > 9007199254740991 {
			return 0, cliError{"usage", 2}
		}
		return n, nil
	}
	return fallback, nil
}
func copyValue(value any) any {
	b, _ := kernel.CanonicalJSON(value)
	v, _ := kernel.DecodeJSON(b)
	return v
}
func readInputFile(filename string) ([]byte, error) {
	var r io.Reader = os.Stdin
	if filename != "-" {
		f, e := os.Open(filename)
		if e != nil {
			return nil, cliError{"input_io", 6}
		}
		defer f.Close()
		r = f
	}
	b, e := io.ReadAll(io.LimitReader(r, inputLimit+1))
	if e != nil {
		return nil, cliError{"input_io", 6}
	}
	if len(b) > inputLimit {
		return nil, cliError{"input_too_large", 3}
	}
	if !utf8.Valid(b) {
		return nil, cliError{"invalid_json", 3}
	}
	return b, nil
}
func loadWriteInput(a arguments) (writeInput, error) {
	in := writeInput{a: a, sources: []any{}}
	stdin := 0
	for _, name := range []string{"body", "sources", "source-text"} {
		if a.flags[name] == "-" {
			stdin++
		}
	}
	_, hasBody := a.flags["body"]
	_, hasContent := a.flags["content"]
	if stdin > 1 || hasBody && hasContent {
		return in, cliError{"usage", 2}
	}
	for _, name := range []string{"body", "sources"} {
		if filename, ok := a.flags[name]; ok {
			b, e := readInputFile(filename)
			if e != nil {
				return in, e
			}
			v, refusal := kernel.DecodeJSON(b)
			if refusal != nil {
				return in, refusal
			}
			if name == "body" {
				var ok bool
				in.body, ok = v.(map[string]any)
				if !ok {
					return in, cliError{"invalid_shape", 3}
				}
			} else {
				var ok bool
				in.sources, ok = v.([]any)
				if !ok {
					return in, cliError{"invalid_shape", 3}
				}
			}
		}
	}
	locator, hasSession := a.flags["source-session"]
	filename, hasText := a.flags["source-text"]
	if hasSession != hasText {
		return in, invalidSourceSession{}
	}
	if hasSession {
		parts := strings.SplitN(locator, ":", 3)
		if runtime, session, message, ok := scan.ParseSessionLocator(locator); ok {
			parts = []string{runtime, session, message}
		}
		if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
			return in, invalidSourceSession{}
		}
		b, e := readInputFile(filename)
		if e != nil {
			return in, e
		}
		in.text = string(b)
		digest := sha256.Sum256(b)
		in.session = map[string]any{"runtime": parts[0], "session": parts[1], "message": parts[2], "digest": "sha256:" + hex.EncodeToString(digest[:])}
	}
	return in, nil
}

func writeCLI(ctx context.Context, h home, c localConfig, a arguments) (any, error) {
	cmd := a.pos[0]
	if len(a.pos) != 2 {
		return nil, cliError{"usage", 2}
	}
	common := []string{"space", "id", "idempotency-key", "at", "expected-generation", "body", "content"}
	switch cmd {
	case "add":
		common = append(common, "version", "subject", "issuer", "perspective", "perspective-principal", "schema", "schema-version", "statement-kind", "admission-class", "valid-from", "valid-to", "confirmed-at", "sources", "source-session", "source-text")
	case "assess":
		common = append(common, "version", "expected-version", "expected-id", "expected-token", "issuer", "perspective", "perspective-principal", "admission-class", "kind", "executor", "result", "polarity", "origin", "source-requirement", "sources", "source-session", "source-text")
	case "revise":
		common = append(common, "version", "relation", "expected-version", "expected-id", "expected-token", "issuer", "admission-class", "sources", "source-session", "source-text")
	case "promote":
		common = []string{"space", "to", "id", "idempotency-key", "at", "expected-generation", "version"}
	}
	if e := a.allow(common...); e != nil {
		return nil, e
	}
	if cmd == "revise" && hasSourceFlags(a) {
		if a.flags["relation"] != "replace" && a.flags["relation"] != "correct" {
			return nil, cliError{"usage", 2}
		}
		if !attributedReviseEnabled {
			return nil, cliError{"feature_not_enabled", 2}
		}
	}
	if cmd == "revise" || cmd == "assess" {
		_, number := a.flags["expected-version"]
		_, token := a.flags["expected-token"]
		if !number && !token {
			return nil, missingWriteToken{}
		}
		_, expectedID := a.flags["expected-id"]
		if number && token || token && expectedID {
			return nil, cliError{"usage", 2}
		}
	}
	key, e := a.required("idempotency-key")
	if e != nil {
		return nil, e
	}
	id := defaultFlag(a, "id", "record:"+key)
	if id == "" {
		return nil, cliError{"usage", 2}
	}
	spaces, e := selected(c, a.flags["space"])
	if e != nil {
		return nil, e
	}
	if len(spaces) != 1 {
		return nil, cliError{"space_required", 2}
	}
	selectedSpace := spaces[0]
	k, e := h.authenticatedKey(ctx, c)
	if e != nil {
		return nil, e
	}
	in, e := loadWriteInput(a)
	if e != nil {
		return nil, e
	}
	r, e := openSpace(ctx, selectedSpace)
	if e != nil {
		return nil, e
	}
	var promoted map[string]any
	var citation map[string]any
	if cmd == "promote" {
		to, e := a.required("to")
		if e != nil {
			return nil, e
		}
		target, e := selectSpace(c, to)
		if e != nil {
			return nil, e
		}
		if target.ID == selectedSpace.ID {
			return nil, cliError{"usage", 2}
		}
		targetRepo, err := openSpace(ctx, target)
		if err != nil {
			return nil, err
		}
		if r.VerifiedPolicy().OwnerNamespace() != targetRepo.VerifiedPolicy().OwnerNamespace() || r.VerifiedPolicy().OwnerNamespace() == "" && r.VerifiedPolicy().Policy().Owners[0] != targetRepo.VerifiedPolicy().Policy().Owners[0] {
			return nil, cliError{"cross_owner_promotion", 3}
		}
		promoted, e = promotionSource(ctx, r, k, a)
		if e != nil {
			return nil, e
		}
		b, refusal := kernel.CanonicalJSON(map[string]any{"space": selectedSpace.ID, "record": recordRef(promoted)})
		if refusal != nil {
			return nil, refusal
		}
		digest, refusal := kernel.DigestJSON(promoted)
		if refusal != nil {
			return nil, refusal
		}
		citation = sourceBody(k.Identity(), string(b), strconv.FormatInt(agentprofile.Object(promoted["envelope"])["version"].(int64), 10))
		citation["original_issuer"] = agentprofile.Object(promoted["envelope"])["issuer"]
		citation["provenance"] = "reported"
		citation["digest"] = map[string]any{"algorithm": "sha256-cjson-v1", "value": digest}
		selectedSpace = target
		r, e = openSpace(ctx, selectedSpace)
		if e != nil {
			return nil, e
		}
	}
	var operation map[string]any
	primaryID := id
	written, e := r.Write(ctx, space.WriteRequest{Signer: k, MaxRetries: writeRetries, Precondition: func(snapshot map[string]any, cursor string) error {
		if cmd != "revise" && cmd != "assess" || priorWrite(snapshot, k.Identity(), selectedSpace.ID, key) != nil {
			return nil // The kernel still checks current authority and exact replay intent.
		}
		return checkWriteTarget(snapshot, selectedSpace.ID, cursor, a)
	}, Build: func(snapshot map[string]any) (map[string]any, error) {
		prior := priorWrite(snapshot, k.Identity(), selectedSpace.ID, key)
		generation := agentprofile.Object(snapshot["runtime"])["erasure_generation"].(int64)
		if prior != nil {
			generation = prior["expected_generation"].(int64)
		}
		generation, e = numberFlag(a, "expected-generation", generation, 0)
		if e != nil {
			return nil, e
		}
		now := defaultFlag(a, "at", time.Now().UTC().Format("2006-01-02T15:04:05Z"))
		in.validFrom = now
		priorRecords := agentprofile.Array(prior["proposals"])
		if prior["op"] == "revise" {
			priorRecords = []any{prior["revision"]}
		}
		for _, raw := range priorRecords {
			env := agentprofile.Object(agentprofile.Object(raw)["envelope"])
			if env["id"] == id {
				if from, ok := agentprofile.Object(env["valid"])["from"].(string); ok {
					in.validFrom = from
				}
			}
		}
		operation = map[string]any{"op": "admit", "context": map[string]any{"actor": k.Identity(), "at": now, "admission_class": defaultFlag(a, "admission-class", "machine_observation"), "retention_context": map[string]any{"audience": "aud:private", "purpose": "purpose:read"}}, "idempotency_key": key, "expected_generation": generation}
		var record map[string]any
		switch cmd {
		case "revise":
			record, e = in.revision(snapshot, prior, selectedSpace.ID, k.Identity(), id, operation)
		case "assess":
			record, e = in.assessment(snapshot, selectedSpace.ID, k.Identity(), id)
		case "promote":
			record = copyValue(promoted).(map[string]any)
			env := agentprofile.Object(record["envelope"])
			delete(env, "submitter")
			delete(env, "recorded")
			delete(env, "admission_class")
			env["id"], env["version"], env["space"] = id, int64(1), selectedSpace.ID
			env["issuer"], env["representation_ref"] = k.Identity(), nil
			env["perspective"] = map[string]any{"kind": "own", "principal": k.Identity()}
			env["lineage"] = "unknown"
		default:
			kind := a.pos[1]
			record, e = in.newRecord(selectedSpace.ID, k.Identity(), id, kind)
		}
		if e != nil {
			return nil, e
		}
		if cmd == "revise" {
			if replacement := agentprofile.Object(operation["replacement"]); replacement != nil {
				primaryID = agentprofile.Object(replacement["envelope"])["id"].(string)
				if hasSourceFlags(a) {
					env := agentprofile.Object(replacement["envelope"])
					if env["kind"] != "assertion" {
						return nil, cliError{"usage", 2}
					}
					stem := primaryID + ":v" + strconv.FormatInt(env["version"].(int64), 10)
					batch, e := in.attributedRecords(replacement, stem, k.Identity(), nil)
					if e != nil {
						return nil, e
					}
					if len(batch) > 1 {
						operation["auxiliaries"] = batch[1:]
					}
				}
			}
			return operation, nil
		}
		batch, e := in.attributedRecords(record, id, k.Identity(), citation)
		if e != nil {
			return nil, e
		}
		operation["proposals"] = batch
		return operation, nil
	}})
	if e != nil {
		// The documentary profile quarantines scanner hits during admission.
		// Render findings only for a matching scan; unrelated refusals stay typed.
		if e.Error() == "quarantined" && operation != nil {
			if findings := proposalFindings(operation, r.VerifiedPolicy().Policy().Limits); len(findings) > 0 {
				e = &space.ScanError{Findings: findings}
			}
		}
		var hit *space.ScanError
		if errors.As(e, &hit) {
			return map[string]any{"findings": hit.Findings}, e
		}
		return nil, e
	}
	// Receipt refs are authenticated replay outputs. Resolve the primary record
	// there, including an idempotent replay with a later verified cursor.
	var version int64
	for _, raw := range agentprofile.Array(written.Receipt["refs"]) {
		ref := agentprofile.Object(raw)
		if ref["id"] == primaryID {
			version = ref["version"].(int64)
		}
	}
	if version == 0 {
		return nil, cliError{"internal", 6}
	}
	record, e := findRecord(r.Snapshot(), primaryID, version)
	if e != nil {
		return nil, e
	}
	kind := agentprofile.Object(record["envelope"])["kind"].(string)
	path := "records/" + kind + "/" + hex.EncodeToString([]byte(primaryID)) + "/" + strconv.FormatInt(version, 10) + ".json"
	commits, e := gitCall(ctx, selectedSpace.ClonePath, "log", "--first-parent", "--reverse", "--format=%H", r.Cursor(), "--", path)
	if e != nil || len(strings.Fields(string(commits))) == 0 {
		return nil, cliError{"git_failed", 6}
	}
	return writeData{primaryID, version, strings.Fields(string(commits))[0], r.Cursor(), written.Receipt}, nil
}

func recordRef(record map[string]any) map[string]any {
	e := agentprofile.Object(record["envelope"])
	return agentprofile.Ref(e["id"].(string), e["version"].(int64))
}
func findRecord(snapshot map[string]any, id string, version int64) (map[string]any, error) {
	var selected map[string]any
	for _, raw := range agentprofile.Array(snapshot["records"]) {
		record := agentprofile.Object(raw)
		e := agentprofile.Object(record["envelope"])
		if e["id"] == id && (version == 0 || e["version"] == version) && (selected == nil || e["version"].(int64) > agentprofile.Object(selected["envelope"])["version"].(int64)) {
			selected = record
		}
	}
	if selected == nil {
		return nil, cliError{"record_not_found", 3}
	}
	return copyValue(selected).(map[string]any), nil
}
func priorWrite(snapshot map[string]any, actor, spaceID, key string) map[string]any {
	for _, raw := range agentprofile.Array(agentprofile.Object(snapshot["runtime"])["idempotency"]) {
		entry := agentprofile.Object(raw)
		if entry["actor"] == actor && entry["space"] == spaceID && entry["key"] == key {
			v, refusal := kernel.DecodeJSON([]byte(entry["canonical_request"].(string)))
			if refusal == nil {
				return agentprofile.Object(v)
			}
		}
	}
	return nil
}
func (in writeInput) envelope(spaceID, actor, id, kind string) (map[string]any, error) {
	a := in.a
	version, e := numberFlag(a, "version", 1, 1)
	if e != nil {
		return nil, e
	}
	issuer := defaultFlag(a, "issuer", actor)
	valid := map[string]any{"kind": "known", "from": defaultFlag(a, "valid-from", in.validFrom), "to": nil, "precision": "second"}
	if value, ok := a.flags["valid-to"]; ok {
		valid["to"] = value
	}
	var confirmed any
	if value, ok := a.flags["confirmed-at"]; ok {
		confirmed = value
	}
	return map[string]any{"id": id, "version": version, "kind": kind, "schema": nil, "subject": defaultFlag(a, "subject", actor), "issuer": issuer, "representation_ref": nil, "perspective": map[string]any{"kind": defaultFlag(a, "perspective", "own"), "principal": defaultFlag(a, "perspective-principal", issuer)}, "space": spaceID, "valid": valid, "confirmed_at": confirmed, "lineage": "unknown", "disclosure": map[string]any{"audiences": []any{"aud:private", "aud:public"}, "purposes": []any{"purpose:read"}, "field_classes": []any{"public"}, "retain_until": nil, "declassification": []any{}}, "context": "real"}, nil
}
func (in writeInput) newRecord(spaceID, actor, id, kind string) (map[string]any, error) {
	if kind != "assertion" && kind != "source" && kind != "assessment" && kind != "justification" {
		return nil, cliError{"usage", 2}
	}
	env, e := in.envelope(spaceID, actor, id, kind)
	if e != nil {
		return nil, e
	}
	var body any = copyValue(in.body)
	if kind == "assertion" {
		n, e := numberFlag(in.a, "schema-version", 1, 1)
		if e != nil {
			return nil, e
		}
		env["schema"] = agentprofile.Ref(defaultFlag(in.a, "schema", "schema:assumption"), n)
		if in.body == nil {
			text, ok := in.a.flags["content"]
			if !ok {
				return nil, cliError{"usage", 2}
			}
			body = map[string]any{"statement_kind": defaultFlag(in.a, "statement-kind", "fact"), "slot": "[]", "content": []any{map[string]any{"field": "value", "value": text}}, "authority_receipt": nil}
		} else if _, ok := in.a.flags["statement-kind"]; ok {
			return nil, cliError{"usage", 2}
		}
	} else {
		if in.body == nil {
			return nil, cliError{"usage", 2}
		}
		for _, flag := range []string{"content", "schema", "schema-version", "statement-kind"} {
			if _, ok := in.a.flags[flag]; ok {
				return nil, cliError{"usage", 2}
			}
		}
	}
	return map[string]any{"envelope": env, "body": body}, nil
}
func auxiliaryEnvelope(record map[string]any, id, kind string) map[string]any {
	e := copyValue(record["envelope"]).(map[string]any)
	e["id"], e["version"], e["kind"], e["schema"] = id, int64(1), kind, nil
	return e
}
func sourceBody(actor, object, revision string) map[string]any {
	return map[string]any{"owner": actor, "source_kind": "artifact", "object": object, "revision": revision, "digest": nil, "provenance": "direct", "availability": "unavailable", "origin": object, "original_issuer": actor, "carrier": nil, "excerpt": nil, "retention_admission": nil}
}
func proposalFindings(operation map[string]any, limits space.Limits) []scan.Finding {
	records := agentprofile.Array(operation["proposals"])
	if operation["op"] == "revise" {
		records = []any{operation["revision"]}
		if operation["replacement"] != nil {
			records = append(records, operation["replacement"])
		}
		records = append(records, agentprofile.Array(operation["auxiliaries"])...)
	}
	findings := []scan.Finding{}
	for _, record := range records {
		findings = append(findings, scan.Scan(record, scan.Limits{MaxCanonicalBytes: int(limits.MaxRecordBytes), MaxStringBytes: int(limits.MaxFieldBytes), MaxArrayLength: 10000})...)
	}
	return findings
}

func (in writeInput) revision(snapshot, prior map[string]any, spaceID, actor, id string, operation map[string]any) (map[string]any, error) {
	a := in.a
	relation := a.flags["relation"]
	if relation != "replace" && relation != "withdraw" && relation != "correct" && relation != "challenge" {
		return nil, cliError{"usage", 2}
	}
	target, expected, e := pinnedWriteTarget(snapshot, spaceID, a)
	if e != nil {
		return nil, e
	}
	if prior["op"] == "revise" && a.flags["expected-token"] != "" {
		expected = agentprofile.Object(prior["expected_version"])
	}
	targetEnv := agentprofile.Object(target["envelope"])
	// --version chooses the target, never the new revision record's version.
	envelopeInput := in
	envelopeInput.a.flags = make(map[string]string, len(a.flags))
	for k, v := range a.flags {
		if k != "version" {
			envelopeInput.a.flags[k] = v
		}
	}
	env, e := envelopeInput.envelope(spaceID, actor, id, "revision")
	if e != nil {
		return nil, e
	}
	env["subject"] = targetEnv["subject"]
	// An issuer's revision stays in its target's exact read perspective. A
	// different issuer's challenge retains the challenger's own perspective;
	// existing representation checks still refuse foreign replacements.
	if targetEnv["issuer"] == env["issuer"] {
		env["perspective"] = copyValue(targetEnv["perspective"])
	}
	body := map[string]any{"relation": relation, "target": recordRef(target), "replacement": nil, "availability": nil, "authority_receipt": nil}
	var replacement any
	if relation == "replace" || relation == "correct" {
		r := copyValue(target).(map[string]any)
		re := agentprofile.Object(r["envelope"])
		delete(re, "submitter")
		delete(re, "recorded")
		delete(re, "admission_class")
		re["version"] = re["version"].(int64) + 1
		if in.body != nil {
			r["body"] = copyValue(in.body)
		} else if content, ok := a.flags["content"]; ok && re["kind"] == "assertion" {
			agentprofile.Object(r["body"])["content"] = []any{map[string]any{"field": "value", "value": content}}
		} else {
			return nil, cliError{"usage", 2}
		}
		replacement = r
		body["replacement"] = recordRef(r)
	} else {
		_, hasContent := a.flags["content"]
		if in.body != nil || hasContent {
			return nil, cliError{"usage", 2}
		}
	}
	record := map[string]any{"envelope": env, "body": body}
	operation["op"], operation["revision"], operation["replacement"], operation["expected_version"] = "revise", record, replacement, expected
	return record, nil
}

func (in writeInput) assessment(snapshot map[string]any, spaceID, actor, id string) (map[string]any, error) {
	a := in.a
	kind, e := a.required("kind")
	if e != nil {
		return nil, e
	}
	if _, ok := a.flags["content"]; ok {
		return nil, cliError{"usage", 2}
	}
	target, _, e := pinnedWriteTarget(snapshot, spaceID, a)
	if e != nil {
		return nil, e
	}
	env, e := in.envelope(spaceID, actor, id, "assessment")
	if e != nil {
		return nil, e
	}
	env["version"] = int64(1)
	env["subject"] = agentprofile.Object(target["envelope"])["subject"]
	ref := recordRef(target)
	body := in.body
	if body == nil {
		var literal any
		if agentprofile.Object(target["envelope"])["kind"] == "assertion" {
			literal = map[string]any{"assertion": ref, "polarity": defaultFlag(a, "polarity", "support")}
		}
		policy := agentprofile.Object(agentprofile.Object(snapshot["policy"])["evidence"])
		body = map[string]any{"check_kind": kind, "executor": defaultFlag(a, "executor", "model"), "result": defaultFlag(a, "result", "pass"), "pins": map[string]any{"subject": ref, "rule": agentprofile.Ref("check:"+kind, 1), "policy": policy["policy_pin"], "environment": policy["environment_pin"]}, "target": literal, "sources": []any{}, "origin": defaultFlag(a, "origin", "origin:"+id), "source_requirement": defaultFlag(a, "source-requirement", "current"), "usable_until": nil, "declassification": nil}
	} else {
		body = copyValue(body).(map[string]any)
		b, _ := kernel.CanonicalJSON(agentprofile.Object(body["pins"])["subject"])
		want, _ := kernel.CanonicalJSON(ref)
		if body["check_kind"] != kind || string(b) != string(want) {
			return nil, cliError{"usage", 2}
		}
		for _, flag := range []string{"executor", "result", "polarity", "origin", "source-requirement"} {
			if _, ok := a.flags[flag]; ok {
				return nil, cliError{"usage", 2}
			}
		}
	}
	return map[string]any{"envelope": env, "body": body}, nil
}

func promotionSource(ctx context.Context, r *space.Repository, k identityKey, a arguments) (map[string]any, error) {
	principal, ok, e := authenticatedReadPrincipal(ctx, r.VerifiedPolicy().Policy(), k)
	if e != nil {
		return nil, e
	}
	if !ok {
		return nil, cliError{"not_authorized", 3}
	}
	n, e := numberFlag(a, "version", 0, 1)
	if e != nil {
		return nil, e
	}
	snapshot := r.Snapshot()
	record, e := findRecord(snapshot, a.pos[1], n)
	if e != nil {
		return nil, e
	}
	env := agentprofile.Object(record["envelope"])
	if env["kind"] != "assertion" {
		return nil, cliError{"unsupported_operation", 3}
	}
	p := agentprofile.Object(snapshot["policy"])
	runtime := agentprofile.Object(snapshot["runtime"])
	audience := "aud:private"
	if principal == "public" {
		audience = "aud:public"
	}
	q := map[string]any{"kind": "explain", "principal": principal, "purpose": "purpose:read", "audience": audience, "scope": map[string]any{"space": env["space"], "subject": env["subject"], "schema": env["schema"], "targets": []any{recordRef(record)}}, "projection_rule": agentprofile.Ref(agentprofile.RuleID(env["issuer"].(string), env["perspective"]), 1), "evidence_policy": agentprofile.Object(p["evidence"])["ref"], "policy": p["revision"], "cut": map[string]any{"memory": runtime["memory_cut"], "sources": runtime["source_cuts"]}, "valid_at": "any", "now": defaultFlag(a, "at", time.Now().UTC().Format("2006-01-02T15:04:05Z")), "mode": "real", "bounds": agentprofile.Object(p["limits"])["read"], "usable_until": nil, "render": "full", "since": nil}
	view, e := r.Read(q)
	if e != nil {
		return nil, e
	}
	for _, raw := range agentprofile.Array(view["items"]) {
		ref := agentprofile.Object(agentprofile.Object(raw)["ref"])
		if ref["id"] == env["id"] && ref["version"] == env["version"] {
			return record, nil
		}
	}
	return nil, cliError{"record_not_found", 3}
}

// sessionRevision preserves an explicit locator kind. Bare decimal positions
// are indexes; other runtime-provided IDs are messages. Origin retains the input.
func sessionRevision(message string) string {
	if strings.HasPrefix(message, "message:") || strings.HasPrefix(message, "index:") {
		return message
	}
	decimal := message != ""
	for _, c := range message {
		decimal = decimal && c >= '0' && c <= '9'
	}
	if decimal {
		return "index:" + message
	}
	return "message:" + message
}

func hasSourceFlags(a arguments) bool {
	for _, name := range []string{"sources", "source-session", "source-text"} {
		if _, present := a.flags[name]; present {
			return true
		}
	}
	return false
}

// attributedRecords is shared by add, assess, promotion and gated replacement
// writes. The caller chooses the auxiliary namespace; input sources stay immutable.
func (in writeInput) attributedRecords(record map[string]any, stem, actor string, citation map[string]any) ([]any, error) {
	sources := append([]any{}, in.sources...)
	batch := []any{record}
	if in.session != nil || citation != nil {
		body := citation
		if in.session != nil {
			locator, refusal := kernel.CanonicalJSON(map[string]any{"runtime": in.session["runtime"], "session": in.session["session"], "message": in.session["message"]})
			if refusal != nil {
				return nil, refusal
			}
			body = sourceBody(actor, "session:"+in.session["session"].(string), sessionRevision(in.session["message"].(string)))
			body["owner"] = "runtime:" + in.session["runtime"].(string)
			body["provenance"] = "reported"
			body["digest"] = map[string]any{"algorithm": "sha256-bytes-v1", "value": strings.TrimPrefix(in.session["digest"].(string), "sha256:")}
			body["origin"] = string(locator)
			body["excerpt"] = in.text
			body["retention_admission"] = agentprofile.Ref("retention:"+stem, 1)
		}
		source := map[string]any{"envelope": auxiliaryEnvelope(record, stem+":source", "source"), "body": body}
		batch = append(batch, source)
		sources = append(sources, recordRef(source))
	}
	if len(sources) > 0 {
		if agentprofile.Object(record["envelope"])["kind"] == "assessment" {
			body := agentprofile.Object(record["body"])
			body["sources"] = append(agentprofile.Array(body["sources"]), sources...)
		} else if agentprofile.Object(record["envelope"])["kind"] == "assertion" {
			premises := []any{}
			for _, source := range sources {
				premises = append(premises, map[string]any{"kind": "source", "source": source})
			}
			batch = append(batch, map[string]any{"envelope": auxiliaryEnvelope(record, stem+":basis", "justification"), "body": map[string]any{"target": map[string]any{"assertion": recordRef(record), "polarity": "support"}, "premises": premises, "rule": agentprofile.Ref("rule:documentary-citation", 1), "rule_kind": "declared_rationale", "role": "documentary_basis", "check": nil}})
		} else {
			return nil, cliError{"usage", 2}
		}
	}
	return batch, nil
}
