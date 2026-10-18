package conformance

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/relux-works/swarma-memory/kernel"
)

// Executor executes operations in order and then the final query. Execution
// failures are harness errors, distinct from a valid report containing refusals.
type Executor interface{ Execute(Input) (Report, error) }

// Run returns one verdict per vector in load order, or a harness error. The
// caller must not count partial results as a successful suite.
func Run(vectors []Vector, executor Executor) ([]Verdict, error) {
	if len(vectors) == 0 || executor == nil {
		return nil, fmt.Errorf("harness: nonempty suite and executor are required")
	}
	verdicts := make([]Verdict, 0, len(vectors))
	for _, v := range vectors {
		report, err := executor.Execute(v.Input())
		if err != nil {
			return nil, fmt.Errorf("harness: %s: %w", v.ID(), err)
		}
		verdict := Compare(v, report)
		verdict.Parts = CompareParts(v, report)
		verdicts = append(verdicts, verdict)
	}
	return verdicts, nil
}

// CheckRatchet requires every listed ID to exist and pass; newly passing IDs
// are returned in suite order. Blank lines and # comments are permitted.
func CheckRatchet(verdicts []Verdict, text string) ([]string, error) {
	results := map[string]bool{}
	for _, v := range verdicts {
		if _, ok := results[v.ID]; ok {
			return nil, fmt.Errorf("duplicate result %s", v.ID)
		}
		results[v.ID] = v.Pass
	}
	required := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		id := strings.TrimSpace(line)
		if id == "" || strings.HasPrefix(id, "#") {
			continue
		}
		if required[id] {
			return nil, fmt.Errorf("ratchet: duplicate id %s", id)
		}
		required[id] = true
		pass, ok := results[id]
		if !ok {
			return nil, fmt.Errorf("ratchet: unknown id %s", id)
		}
		if !pass {
			return nil, fmt.Errorf("ratchet: required vector %s failed", id)
		}
	}
	var added []string
	for _, v := range verdicts {
		if v.Pass && !required[v.ID] {
			added = append(added, v.ID)
		}
	}
	return added, nil
}

// KernelExecutor drives reads and transactions from input snapshots. Expected results
// and comparison metadata never enter the state or its handle generator.
type KernelExecutor struct{ Schemas *kernel.Schemas }

func freshHandle() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func refusalTree(r *kernel.Refusal) map[string]any {
	return map[string]any{"type": r.Type, "code": string(r.Code), "retryable": r.Retryable}
}
func unsupported() map[string]any {
	r, _ := kernel.NewRefusal(kernel.UnsupportedOperation)
	return refusalTree(r)
}
func (e KernelExecutor) Execute(input Input) (Report, error) {
	state, r := kernel.NewState(input.InitialState, e.Schemas, freshHandle)
	if r != nil {
		return nil, fmt.Errorf("initial snapshot: %s", r.Code)
	}
	results := make([]any, 0, len(input.Operations))
	for index, raw := range input.Operations {
		op := raw.(map[string]any)
		var result map[string]any
		switch op["op"] {
		case "admit", "admit_raw", "revise", "erase", "restore", "reconcile_restore", "deliver", "revoke", "declassify", "revoke_declassification", "control", "request_check":
			var r *kernel.Refusal
			result, r = state.Write(op)
			if r != nil {
				result = refusalTree(r)
			}
		case "load":
			var r *kernel.Refusal
			result, r = state.SeedLoad(op["actor"].(string), op["hidden_work"].(int64))
			if r != nil {
				result = refusalTree(r)
			}
		case "capture":
			var r *kernel.Refusal
			result, r = state.Capture(int64(index), op["query"].(map[string]any))
			if r != nil {
				result = refusalTree(r)
			}
		case "set_availability":
			var r *kernel.Refusal
			result, r = state.SetAvailability(op)
			if r != nil {
				result = refusalTree(r)
			}
		default:
			return nil, fmt.Errorf("unsupported harness operation %q", op["op"])
		}
		results = append(results, result)
	}
	snapshot := state.Snapshot()
	runtime := snapshot["runtime"].(map[string]any)
	refs := []any{}
	custody := []any{}
	for _, raw := range snapshot["records"].([]any) {
		env := raw.(map[string]any)["envelope"].(map[string]any)
		refs = append(refs, map[string]any{"id": env["id"], "version": env["version"]})
	}
	for _, raw := range runtime["custody"].([]any) {
		item := raw.(map[string]any)
		if item["present"] == true {
			custody = append(custody, item["id"])
		}
	}
	post := map[string]any{"record_refs": refs, "erased_refs": clone(runtime["erased"]), "custody_present": custody, "dirty": clone(runtime["dirty"]), "control_observations": clone(runtime["control_observations"]), "external_effects": clone(runtime["external_effects"])}
	for _, key := range inventories {
		list := post[key].([]any)
		sort.Slice(list, func(i, j int) bool {
			a, _ := kernel.CanonicalJSON(list[i])
			b, _ := kernel.CanonicalJSON(list[j])
			return bytes.Compare(a, b) < 0
		})
	}
	result, r := state.Read(input.Query)
	if r != nil {
		result = refusalTree(r)
	}
	return Report{"operation_results": results, "result": result, "postconditions": post}, nil
}
