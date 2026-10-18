package kernel

// Unsupported is the stage-1 baseline. It refuses all four kernel methods and
// changes no state. Later implementations replace it without changing Kernel.
type Unsupported struct{}

var _ Kernel = Unsupported{}

func (Unsupported) Admit(Context, []Record) (Receipts, *Refusal) {
	return Receipts{}, refusal(UnsupportedOperation)
}
func (Unsupported) Recall(Context, Query) (View, *Refusal) {
	return View{}, refusal(UnsupportedOperation)
}
func (Unsupported) Explain(Context, VersionRef, Bounds) (Explanation, *Refusal) {
	return Explanation{}, refusal(UnsupportedOperation)
}
func (Unsupported) Changes(Context, Cursor, Bounds) (ChangeSet, *Refusal) {
	return ChangeSet{}, refusal(UnsupportedOperation)
}
