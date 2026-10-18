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

// placeholder: defined by later stage-1 tasks
type Context struct{}

// placeholder: defined by later stage-1 tasks
type Record struct{}

// placeholder: defined by later stage-1 tasks
type Receipts struct{}

// placeholder: defined by later stage-1 tasks
type Refusal struct{}

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
