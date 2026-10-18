package kernel

// Kernel defines the memory operations driven directly by the conformance runner.
type Kernel interface {
	// Admit checks a batch of records against the space policy, the schemas,
	// revision authority and expected versions, and returns receipts or a typed refusal.
	Admit(ctx Context, batch []Record) (Receipts, *Refusal)
	// Recall evaluates a query under a named projection rule over admitted records.
	Recall(ctx Context, q Query) (View, *Refusal)
	// Explain returns the support graph behind one assertion version, within bounds.
	Explain(ctx Context, a VersionRef, b Bounds) (Explanation, *Refusal)
	// Changes lists memory's own changes after a cursor.
	Changes(ctx Context, c Cursor, b Bounds) (ChangeSet, *Refusal)
}

// Context is authenticated by the intake adapter, never by proposed records.
type Context struct {
	Actor, At, AdmissionClass, IdempotencyKey string
	ExpectedGeneration                        int64
	RetentionContext                          RetentionContext
	// ReadQuery supplies the complete pinned query for Explain and Changes.
	ReadQuery Query
}

type RetentionContext struct{ Audience, Purpose string }

// Record is a closed proposal in the exact decoded JSON value model.
type Record map[string]any

// Receipts carries one atomic write receipt.
type Receipts struct{ Receipt map[string]any }

// Query is the complete closed read envelope, including authorization, public
// configuration pins, knowledge cut, context and per-component bounds.
type Query map[string]any

// View is the complete view wire value. Every successful request has one fresh
// opaque handle shared by all its polarity records.
type View map[string]any

// VersionRef identifies an exact admitted record (id and positive version).
type VersionRef map[string]any

// Bounds names roots, rules, source_resolutions and explanations.
type Bounds map[string]any

// Explanation retains the full view and both extended polarity records.
type Explanation map[string]any

// Cursor carries the protected capture operation index as since (or null).
type Cursor map[string]any

// ChangeSet retains the full view with its authorized changes object.
type ChangeSet map[string]any
