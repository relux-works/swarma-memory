package main

import (
	"context"

	"github.com/relux-works/swarma-memory/go/sign/sshagent"
	"github.com/relux-works/swarma-memory/go/space"
)

type possessionContextKey struct{}
type agentPrincipal struct{ identity, key, socket string }
type possessionChecks struct{ results map[agentPrincipal]error }

// Keep authentication failures distinct from optional directory diagnostics.
// In particular, sync/check must not turn a failed proof into successful data.
type possessionFailure struct{ error }

func (e *possessionFailure) Unwrap() error { return e.error }

// requirePossession caches one attempt only in the current executeCLI context.
// Nothing is cached across commands, processes, configuration edits or key IDs.
// Loading a localfile key already establishes possession as before.
func requirePossession(ctx context.Context, k identityKey) error {
	agent, ok := k.(*sshagent.Key)
	if !ok {
		return nil
	}
	id := agentPrincipal{agent.Identity(), agent.ID(), agent.Socket()}
	checks, _ := ctx.Value(possessionContextKey{}).(*possessionChecks)
	if checks != nil {
		if e, found := checks.results[id]; found {
			return e
		}
	}
	var e error
	if failure := agent.ProvePossession(); failure != nil {
		e = &possessionFailure{failure}
	}
	if checks != nil {
		checks.results[id] = e
	}
	return e
}

func (h home) authenticatedKey(ctx context.Context, c localConfig) (identityKey, error) {
	k, e := h.key(c)
	if e != nil {
		return nil, e
	}
	if e = requirePossession(ctx, k); e != nil {
		return nil, e
	}
	return k, nil
}

func authenticatedReadPrincipal(ctx context.Context, policy space.Policy, k identityKey) (string, bool, error) {
	principal, ok := readPrincipal(policy, k.Identity(), k.ID())
	if ok && principal != "public" {
		if e := requirePossession(ctx, k); e != nil {
			return "", false, e
		}
	}
	return principal, ok, nil
}
