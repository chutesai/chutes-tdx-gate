package e2ev2

import "sync"

// DefaultBudget is the gate's in-flight memory budget (512 MiB).
const DefaultBudget = 512 << 20

// Budget is the memory every in-flight request holds together: each request reserves what it
// will keep (its body, its plaintext, its parse, its answer) before allocating it, and is refused
// e2e_v2_busy when the budget is spent. Nothing is given back until the request ends.
type Budget struct {
	mu   sync.Mutex
	max  int64
	used int64
	peak int64
}

// NewBudget makes a budget of max bytes (DefaultBudget when max <= 0).
func NewBudget(max int64) *Budget {
	if max <= 0 {
		max = DefaultBudget
	}
	return &Budget{max: max}
}

// Max is the budget's size.
func (b *Budget) Max() int64 { return b.max }

// Used is what in-flight requests hold now.
func (b *Budget) Used() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.used
}

// Peak is the most ever held at once (tests).
func (b *Budget) Peak() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.peak
}

// Lease is one request's share of a budget. A nil Lease charges nothing (tests and tools).
type Lease struct {
	b     *Budget
	held  int64
	never bool // a charge asked for more than the whole budget
}

// Lease starts one request's share.
func (b *Budget) Lease() *Lease { return &Lease{b: b} }

// Charge reserves n more bytes, or reports false (and reserves nothing) when the budget cannot
// hold them now; Refusal then says which refusal that is.
func (l *Lease) Charge(n int64) bool {
	if l == nil || n <= 0 {
		return true
	}
	b := l.b
	b.mu.Lock()
	defer b.mu.Unlock()
	if l.held+n > b.max {
		l.never = true
		return false
	}
	if n > b.max-b.used {
		return false
	}
	b.used += n
	b.peak = max(b.peak, b.used)
	l.held += n
	return true
}

// Refusal is the refusal of a request whose charge failed: e2e_v2_busy (Retry-After 1) when the
// budget is held by other requests now, e2e_v2_malformed when the request needs more than the
// whole budget (it could never be admitted).
func (l *Lease) Refusal() *Refusal {
	if l != nil && l.never {
		return refusal("e2e_v2_malformed")
	}
	return Busy(1)
}

// Release gives back everything the lease holds.
func (l *Lease) Release() {
	if l == nil {
		return
	}
	l.b.mu.Lock()
	l.b.used -= l.held
	l.b.mu.Unlock()
	l.held = 0
}
