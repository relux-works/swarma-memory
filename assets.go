// Package memoryassets supplies immutable public schemas to the standalone CLI.
package memoryassets

import "embed"

//go:embed spec/kernel/schemas/*.json spec/domains/decisions/*.json spec/domains/profiles-synthetic/*.json
var Files embed.FS
