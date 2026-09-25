package audit

import (
	"runtime"
	"time"
)

// ContractInput is one item of a batch request.
type ContractInput struct {
	Name string
	Code []byte
}

// Batch audits many contracts concurrently. Conclusions are filled back at
// the submission index, so output order is stable regardless of completion
// order. A per-contract timeout and panic recovery inside Analyze ensure
// one contract can never affect another.
type Batch struct {
	analyzer *Analyzer
	cache    *Cache
	timeout  time.Duration
	workers  int
}

// NewBatch constructs a batch runner. timeout<=0 disables the per-contract
// deadline; workers<=0 selects min(GOMAXPROCS, len(inputs)).
func NewBatch(a *Analyzer, c *Cache, timeout time.Duration, workers int) *Batch {
	return &Batch{analyzer: a, cache: c, timeout: timeout, workers: workers}
}

// Run analyzes all inputs concurrently and returns one report per input,
// indexed exactly like inputs. The returned slice order never changes
// between runs for the same submission order.
func (b *Batch) Run(inputs []ContractInput) []*Report {
	n := len(inputs)
	results := make([]*Report, n)
	if n == 0 {
		return results
	}

	workers := b.workers
	if workers <= 0 {
		workers = runtime.GOMAXPROCS(0)
	}
	if workers > n {
		workers = n
	}

	type job struct {
		idx int
		in  ContractInput
	}
	jobs := make(chan job)

	// Workers signal completion by writing into results; the collector does
	// not reorder anything because every result knows its submission index.
	done := make(chan struct{}, n)
	for w := 0; w < workers; w++ {
		go func() {
			for j := range jobs {
				results[j.idx] = b.analyzeOne(j.in)
				done <- struct{}{}
			}
		}()
	}
	for i, in := range inputs {
		jobs <- job{idx: i, in: in}
	}
	close(jobs)
	for i := 0; i < n; i++ {
		<-done
	}
	return results
}

// analyzeOne serves one contract, honoring cache and the per-contract
// timeout. It always returns a non-nil report.
func (b *Batch) analyzeOne(in ContractInput) *Report {
	if b.cache != nil {
		if r := b.cache.Get(in.Code); r != nil {
			cp := *r
			cp.Name = in.Name // names are not part of the cache key
			return &cp
		}
	}
	if b.timeout <= 0 {
		return b.finish(in, b.analyzer.Analyze(in.Name, in.Code))
	}

	finished := make(chan *Report, 1)
	go func() {
		finished <- b.analyzer.Analyze(in.Name, in.Code)
	}()
	timer := time.NewTimer(b.timeout)
	defer timer.Stop()
	select {
	case r := <-finished:
		return b.finish(in, r)
	case <-timer.C:
		r := &Report{
			Name:         in.Name,
			InputHash:    HashInput(in.Code),
			ByteLen:      len(in.Code),
			Status:       StatusTimeout,
			RejectDetail: "per-contract analysis deadline exceeded",
			RuleVersions: b.analyzer.ruleVersions(),
		}
		// Timeout reports are intentionally not cached: an unfinished
		// analysis must never be reused as a conclusion.
		return r
	}
}

func (b *Batch) finish(in ContractInput, r *Report) *Report {
	if b.cache != nil && r != nil && r.Status != StatusTimeout {
		b.cache.Put(in.Code, r)
	}
	return r
}
