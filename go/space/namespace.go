package space

import "strings"

// IdentityNamespace is the owner prefix, never a space-id-derived authority.
// Empty denotes the unqualified, single-owner legacy namespace.
func IdentityNamespace(identity string) string {
	i := strings.IndexByte(identity, '/')
	if i <= 0 || i == len(identity)-1 {
		return ""
	}
	return identity[:i]
}

func policyNamespace(p Policy) (string, error) {
	ns := IdentityNamespace(p.Owners[0])
	for _, owner := range p.Owners {
		if IdentityNamespace(owner) != ns {
			return "", fail("mixed_owner_namespace")
		}
	}
	if ns == "" && len(p.Owners) != 1 {
		return "", fail("mixed_owner_namespace")
	}
	return ns, nil
}

func validateNamespace(p Policy, ns string) error {
	check := func(id string) error {
		if strings.Contains(id, "/") && IdentityNamespace(id) == "" || (IdentityNamespace(id) == "") != (ns == "") {
			return fail("identity_owner_mismatch")
		}
		return nil
	}
	for _, owner := range p.Owners {
		if err := check(owner); err != nil {
			return err
		}
		if IdentityNamespace(owner) != ns {
			return fail("mixed_owner_namespace")
		}
	}
	if err := check(p.Author); err != nil {
		return err
	}
	for _, key := range p.Keys {
		if err := check(key.Registration.Identity); err != nil {
			return err
		}
	}
	for _, grant := range p.Readers {
		if err := check(grant.Identity); err != nil {
			return err
		}
	}
	for _, grant := range p.Writers {
		if err := check(grant.Identity); err != nil {
			return err
		}
		if IdentityNamespace(grant.Identity) != ns {
			return fail("cross_owner_writer")
		}
	}
	for _, resolver := range p.Resolvers {
		for _, id := range resolver.Identities {
			if err := check(id); err != nil {
				return err
			}
			if IdentityNamespace(id) != ns {
				return fail("identity_owner_mismatch")
			}
		}
	}
	return nil
}

func (p *VerifiedPolicy) OwnerNamespace() string { return p.namespace }
