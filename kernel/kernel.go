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
}

type RetentionContext struct{ Audience, Purpose string }

// Record is a closed proposal in the exact decoded JSON value model.
type Record map[string]any

// Receipts carries one atomic write receipt.
type Receipts struct{ Receipt map[string]any }

// placeholder: defined by later stage-1 tasks
type Query struct{}

// placeholder: defined by later stage-1 tasks
type View struct{}

// placeholder: defined by later stage-1 tasks
type VersionRef struct{}

// placeholder: defined by later stage-1 tasks
type Bounds struct{}

// placeholder: defined by later stage-1 tasks
type Explanation struct{}

// placeholder: defined by later stage-1 tasks
type Cursor struct{}

// placeholder: defined by later stage-1 tasks
type ChangeSet struct{}
