// Package memoryassets supplies immutable public inputs to the standalone CLI.
package memoryassets

import "embed"

//go:embed spec/kernel/schemas/*.json spec/domains/decisions/assumption.json spec/domains/decisions/decision.json spec/domains/decisions/decision_proposal.json spec/domains/decisions/rule.json spec/domains/profiles-synthetic/*.json spec/kernel/vectors/semantic/*.json conformance/*.txt
var Files embed.FS
