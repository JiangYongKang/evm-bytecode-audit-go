package audit

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

func sampleContracts(t *testing.T) [][]byte {
	t.Helper()
	hexes := []string{
		sampleReentrancy,
		sampleCheckedCall,
		sampleUncheckedCall,
		sampleUnguardedSelfdestruct,
		sampleGuardedSelfdestruct,
		sampleMalformed,
	}
	out := make([][]byte, len(hexes))
	for i, h := range hexes {
		out[i] = mustHex(t, h)
	}
	return out
}

func TestBatchMatchesSerialAndOrderStable(t *testing.T) {
	contracts := sampleContracts(t)
	a := NewAnalyzer()

	// 串行基准
	want := make([]Report, len(contracts))
	for i, c := range contracts {
		want[i] = a.Analyze(c)
	}

	// 并发执行多次，结论与顺序必须稳定。
	for round := 0; round < 5; round++ {
		b := NewBatchAuditor(a, 8)
		results := b.Run(context.Background(), contracts)
		if len(results) != len(contracts) {
			t.Fatalf("round %d: got %d results, want %d", round, len(results), len(contracts))
		}
		for i, r := range results {
			if r.Index != i {
				t.Fatalf("round %d: result position %d has Index=%d, order not stable", round, i, r.Index)
			}
			if r.Err != nil {
				t.Fatalf("round %d: contract %d unexpected err: %v", round, i, r.Err)
			}
			if !reflect.DeepEqual(r.Report, want[i]) {
				t.Fatalf("round %d: contract %d concurrent report differs from serial\nconcurrent=%+v\nserial=%+v",
					round, i, r.Report, want[i])
			}
		}
	}
	for i := range contracts {
		t.Logf("contract[%d] hash=%s status=%s findings=%d reject=%v",
			i, want[i].CodeHash[:12], want[i].Status, len(want[i].Findings), reasonOf(want[i]))
	}
}

func reasonOf(rep Report) string {
	if rep.Reject == nil {
		return "-"
	}
	return string(rep.Reject.Reason)
}

func TestBatchTimeoutIsolation(t *testing.T) {
	contracts := sampleContracts(t)
	b := NewBatchAuditor(NewAnalyzer(), 2)
	b.PerContractTimeout = 50 * time.Millisecond
	// 仅让 0 号合约在分析前卡住，触发超时。
	b.BeforeAnalyze = func(index int) {
		if index == 0 {
			time.Sleep(300 * time.Millisecond)
		}
	}
	results := b.Run(context.Background(), contracts)

	if !errors.Is(results[0].Err, ErrContractTimeout) {
		t.Fatalf("contract 0 should time out, got err=%v", results[0].Err)
	}
	t.Logf("contract[0] timed out as expected: %v", results[0].Err)
	for i := 1; i < len(results); i++ {
		if results[i].Err != nil {
			t.Fatalf("contract %d affected by sibling timeout: %v", i, results[i].Err)
		}
		t.Logf("contract[%d] unaffected: status=%s", i, results[i].Report.Status)
	}
}

func TestBatchCacheMatchesInput(t *testing.T) {
	contracts := sampleContracts(t)
	b := NewBatchAuditor(NewAnalyzer(), 4)

	first := b.Run(context.Background(), contracts)
	// 打乱顺序再跑一次：缓存命中也必须返回与输入匹配的结果。
	shuffled := [][]byte{contracts[3], contracts[0], contracts[5], contracts[1]}
	second := b.Run(context.Background(), shuffled)

	if second[0].Report.CodeHash != first[3].Report.CodeHash ||
		second[1].Report.CodeHash != first[0].Report.CodeHash {
		t.Fatalf("cache returned mismatched results")
	}
	if second[2].Report.Status != StatusRejected {
		t.Fatalf("cached malformed contract should stay REJECTED, got %s", second[2].Report.Status)
	}
	if !reflect.DeepEqual(second[1].Report, first[0].Report) {
		t.Fatalf("cached report differs from original for identical input")
	}
	t.Logf("cache verified: shuffled rerun returns reports matching each input hash")
}
