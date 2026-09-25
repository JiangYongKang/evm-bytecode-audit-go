package audit

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// ErrContractTimeout 表示单个合约分析超时。
var ErrContractTimeout = errors.New("contract analysis timed out")

// BatchResult 是批量审计中一个合约的结果，Index 保证输出顺序稳定。
type BatchResult struct {
	Index  int
	Report Report
	Err    error // 超时等执行层错误
}

// BatchAuditor 并发执行批量审计。
type BatchAuditor struct {
	Analyzer           *Analyzer
	Workers            int
	PerContractTimeout time.Duration

	// BeforeAnalyze 是可选测试钩子，在每次分析前调用。
	BeforeAnalyze func(index int)

	mu    sync.Mutex
	cache map[string]Report
}

// NewBatchAuditor 构造批量审计器。
func NewBatchAuditor(a *Analyzer, workers int) *BatchAuditor {
	if workers <= 0 {
		workers = 4
	}
	return &BatchAuditor{
		Analyzer:           a,
		Workers:            workers,
		PerContractTimeout: 5 * time.Second,
		cache:              make(map[string]Report),
	}
}

func (b *BatchAuditor) cacheKey(code []byte) string {
	return RulesetID(b.Analyzer.Rules) + ":" + CodeHashOf(code)
}

// analyzeOne 带超时地分析单个合约；超时/失败不影响其它合约。
func (b *BatchAuditor) analyzeOne(ctx context.Context, index int, code []byte) BatchResult {
	res := BatchResult{Index: index}
	key := b.cacheKey(code)

	b.mu.Lock()
	cached, ok := b.cache[key]
	b.mu.Unlock()
	if ok {
		// 缓存键由内容哈希派生，命中即保证与输入匹配；此处再校验一次。
		if cached.CodeHash == CodeHashOf(code) {
			res.Report = cached
			return res
		}
	}

	// 超时窗口覆盖钩子与整个分析过程。
	tctx, cancel := context.WithTimeout(ctx, b.PerContractTimeout)
	defer cancel()

	if b.BeforeAnalyze != nil {
		b.BeforeAnalyze(index)
	}

	type outcome struct{ rep Report }
	done := make(chan outcome, 1)
	go func() {
		done <- outcome{rep: b.Analyzer.Analyze(code)}
	}()

	select {
	case o := <-done:
		res.Report = o.rep
		b.mu.Lock()
		b.cache[key] = o.rep
		b.mu.Unlock()
	case <-tctx.Done():
		if errors.Is(tctx.Err(), context.DeadlineExceeded) {
			res.Err = fmt.Errorf("contract %d: %w", index, ErrContractTimeout)
		} else {
			res.Err = fmt.Errorf("contract %d: %w", index, tctx.Err())
		}
	}
	return res
}

// Run 并发分析所有合约，返回顺序与输入一致的结果。
func (b *BatchAuditor) Run(ctx context.Context, contracts [][]byte) []BatchResult {
	results := make([]BatchResult, len(contracts))
	type job struct{ idx int }
	jobs := make(chan job)
	var wg sync.WaitGroup
	for w := 0; w < b.Workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				results[j.idx] = b.analyzeOne(ctx, j.idx, contracts[j.idx])
			}
		}()
	}
	for i := range contracts {
		jobs <- job{idx: i}
	}
	close(jobs)
	wg.Wait()
	return results
}
