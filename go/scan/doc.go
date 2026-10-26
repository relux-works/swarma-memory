// Package scan checks canonical memory-write trees for secret-format heuristics
// and size limits, returning redacted typed findings. Entropy exemptions apply
// only to documented exact digest/handle and artifact-source locator roles;
// known-token and size detectors remain active. ParseSessionLocator recognizes
// the closed session forms used by the CLI without changing record formats.
// See docs/scanner.md for locator grammars and their security limits.
package scan
