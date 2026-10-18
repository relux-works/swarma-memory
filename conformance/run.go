package conformance

import (
	"bytes"
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
		verdicts = append(verdicts, Compare(v, report))
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

// KernelExecutor is the current unsupported kernel baseline, not an evaluator.
// Placeholder kernel types cannot yet carry JSON inputs. Dispatch uses the four
// Kernel methods where natural; other finite API operations refuse directly.
// Inventories are an unchanged copy of the initial snapshot on every refusal.
type KernelExecutor struct{}

func refusalTree(r *kernel.Refusal) map[string]any {
	return map[string]any{"type": r.Type, "code": string(r.Code), "retryable": r.Retryable}
}
func unsupported() map[string]any {
	r, _ := kernel.NewRefusal(kernel.UnsupportedOperation)
	return refusalTree(r)
}
func queryRefusal(q map[string]any) map[string]any {
	var r *kernel.Refusal
	k := kernel.Unsupported{}
	switch q["kind"] {
	case "recall":
		_, r = k.Recall(kernel.Context{}, kernel.Query{})
	case "explain":
		_, r = k.Explain(kernel.Context{}, kernel.VersionRef{}, kernel.Bounds{})
	case "changes":
		_, r = k.Changes(kernel.Context{}, kernel.Cursor{}, kernel.Bounds{})
	default:
		return unsupported()
	}
	return refusalTree(r)
}
func (KernelExecutor) Execute(input Input) (Report, error) {
	results := make([]any, 0, len(input.Operations))
	for _, raw := range input.Operations {
		op := raw.(map[string]any)
		var result map[string]any
		switch op["op"] {
		case "admit", "admit_raw":
			_, r := (kernel.Unsupported{}).Admit(kernel.Context{}, nil)
			result = refusalTree(r)
		case "capture":
			result = queryRefusal(op["query"].(map[string]any))
		case "revise", "erase", "restore", "reconcile_restore", "deliver", "revoke", "declassify", "revoke_declassification", "load", "set_availability":
			result = unsupported()
		default:
			return nil, fmt.Errorf("unsupported harness operation %q", op["op"])
		}
		results = append(results, result)
	}
	runtime := input.InitialState["runtime"].(map[string]any)
	refs := []any{}
	custody := []any{}
	for _, raw := range input.InitialState["records"].([]any) {
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
	return Report{"operation_results": results, "result": queryRefusal(input.Query), "postconditions": post}, nil
}
