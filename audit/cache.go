package audit

import "sync"

// Cache stores reports keyed by the SHA-256 of the exact input bytes.
//
// On every lookup the supplied bytes are hashed and the cached report's
// InputHash is compared against that hash. A report whose hash mismatches
// is treated as absent (and removed), so a collision, a keying mistake or a
// reused buffer can never return a conclusion for different input. All
// access is mutex-guarded for concurrent use.
type Cache struct {
	mu sync.Mutex
	m  map[string]*Report
}

// NewCache creates an empty cache.
func NewCache() *Cache {
	return &Cache{m: make(map[string]*Report)}
}

// Get returns a cached report matching code exactly, or nil.
func (c *Cache) Get(code []byte) *Report {
	h := HashInput(code)
	c.mu.Lock()
	defer c.mu.Unlock()
	r, ok := c.m[h]
	if !ok || r == nil || r.InputHash != h {
		// Defensive: never return a result that does not match the input.
		if ok {
			delete(c.m, h)
		}
		return nil
	}
	return r
}

// Put stores r only when r is non-nil and its InputHash equals the hash of
// code. It returns whether the report was stored. The cached report is
// shallow-copied so later caller mutation cannot corrupt the cache.
func (c *Cache) Put(code []byte, r *Report) bool {
	if r == nil || r.InputHash != HashInput(code) {
		return false
	}
	stored := *r
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[r.InputHash] = &stored
	return true
}

// Len returns the number of cached reports.
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.m)
}
