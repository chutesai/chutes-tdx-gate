package e2ev2

import (
	"container/heap"
	"sync"
)

const (
	// MaxAgeMS and MaxFutureMS are the ts window: 120 s behind this clock, 60 s ahead.
	MaxAgeMS    = 120_000
	MaxFutureMS = 60_000
	// DefaultReplayEntries is the replay cache's bound (live nonces).
	DefaultReplayEntries = 65536
)

type entry struct {
	ts    int64
	nonce string
}

type entryHeap []entry

func (h entryHeap) Len() int { return len(h) }
func (h entryHeap) Less(i, j int) bool {
	if h[i].ts != h[j].ts {
		return h[i].ts < h[j].ts
	}
	return h[i].nonce < h[j].nonce
}
func (h entryHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *entryHeap) Push(x any)   { *h = append(*h, x.(entry)) }
func (h *entryHeap) Pop() any {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[:n-1]
	return x
}

// ReplayCache keeps every admitted nonce until its ts leaves the window (the SDK's
// endpoint_e2e.ReplayCache): a live entry is never evicted; at the bound a new request is refused
// busy until the oldest leaves; a request not newer than a forgotten entry (the floor) is stale.
type ReplayCache struct {
	mu         sync.Mutex
	maxEntries int
	seen       map[string]int64
	order      entryHeap
	floor      int64
	persist    func(int64) error // the stored high-water mark (Persist)
	mark       int64             // the highest ts persisted
}

// NewReplayCache makes a cache of at most maxEntries live nonces.
func NewReplayCache(maxEntries int) *ReplayCache {
	if maxEntries <= 0 {
		maxEntries = DefaultReplayEntries
	}
	return &ReplayCache{maxEntries: maxEntries, seen: map[string]int64{}, floor: -1}
}

// Len is the number of live nonces.
func (c *ReplayCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.seen)
}

func (c *ReplayCache) expire(now int64) {
	for len(c.order) > 0 && c.order[0].ts < now-MaxAgeMS {
		e := heap.Pop(&c.order).(entry)
		delete(c.seen, e.nonce)
		c.floor = max(c.floor, e.ts)
	}
}

// RaiseFloor refuses (stale) every ts up to ts from now on: after a restart that kept the key,
// the nonces the previous process admitted are unknown, so their window is closed instead.
func (c *ReplayCache) RaiseFloor(ts int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.floor = max(c.floor, ts)
}

// Persist makes Admit call persist(ts) before admitting a ts above every one persisted so far
// (mark): the high-water mark a restarted gate refuses at or below. A failed persist refuses the
// request busy, its nonce unused.
func (c *ReplayCache) Persist(persist func(int64) error, mark int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.persist, c.mark = persist, mark
}

// Admit admits nonce once, or returns its refusal: stale, from the future, replayed, or busy.
func (c *ReplayCache) Admit(nonce string, ts, now int64) *Refusal {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.expire(now)
	if ts < now-MaxAgeMS || ts <= c.floor {
		return refusal("e2e_v2_stale")
	}
	if ts > now+MaxFutureMS {
		return refusal("e2e_v2_from_the_future")
	}
	if _, ok := c.seen[nonce]; ok {
		return refusal("e2e_v2_replayed")
	}
	if len(c.seen) >= c.maxEntries {
		leaves := c.order[0].ts + MaxAgeMS - now // >= 0: the oldest has not left the window
		return Busy(int((leaves + 999) / 1000))
	}
	if c.persist != nil && ts > c.mark {
		if err := c.persist(ts); err != nil {
			return Busy(1)
		}
		c.mark = ts
	}
	c.seen[nonce] = ts
	heap.Push(&c.order, entry{ts: ts, nonce: nonce})
	return nil
}
