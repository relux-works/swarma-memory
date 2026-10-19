package space

import "github.com/relux-works/swarma-memory/go/kernel"

func (r *Repository) configure(state *kernel.State, policy *VerifiedPolicy, operation map[string]any) error {
	if r.config.Profile == nil || policy == nil {
		return nil
	}
	p, rules, err := r.config.Profile(state.Snapshot(), policy, detached(operation))
	if err != nil {
		return err
	}
	if f := state.Configure(p, rules); f != nil {
		return f
	}
	return nil
}

// VerifiedPolicy returns the immutable in-force policy after sync.
func (r *Repository) VerifiedPolicy() *VerifiedPolicy {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.policy
}
