package audit

import (
	"encoding/hex"
	"reflect"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex: %v", err)
	}
	return b
}

// 本地样例合约（均为手工构造的运行时字节码）。
var (
	// 7 个 PUSH1 作 CALL 参数；CALL 之后同块内 SSTORE：典型可重入路径。
	sampleReentrancy = "6000600060006000600060006000" + "f1" + "6001" + "6000" + "55" + "00"
	// CALL 之后 ISZERO + JUMPI 校验返回值。
	sampleCheckedCall = "6000600060006000600060006000" + "f1" + "15" + "6013" + "57" + "5b" + "00"
	// CALL 返回值被立即 POP 丢弃。
	sampleUncheckedCall = "6000600060006000600060006000" + "f1" + "50" + "00"
	// 无 CALLER 鉴权的 SELFDESTRUCT。
	sampleUnguardedSelfdestruct = "6000" + "ff"
	// 有 CALLER 鉴权的 SELFDESTRUCT。
	sampleGuardedSelfdestruct = "33" + "6000" + "ff"
	// 畸形：被截断的 PUSH2。
	sampleMalformed = "6101"
)

func findRule(rep Report, id RuleID) []Evidence {
	var out []Evidence
	for _, f := range rep.Findings {
		if f.RuleID == id {
			out = append(out, f)
		}
	}
	return out
}

func TestAnalyzeReentrancy(t *testing.T) {
	code := mustHex(t, sampleReentrancy)
	rep := NewAnalyzer().Analyze(code)
	t.Logf("input=%s status=%s ruleset=%s", sampleReentrancy, rep.Status, rep.RulesetID)
	for _, f := range rep.Findings {
		t.Logf("  evidence: %s", f)
	}
	if rep.Status != StatusFlagged {
		t.Fatalf("status=%s, want FLAGGED", rep.Status)
	}
	ev := findRule(rep, RuleReentrancy)
	if len(ev) != 1 {
		t.Fatalf("want 1 reentrancy evidence, got %d", len(ev))
	}
	if !reflect.DeepEqual(ev[0].PCs, []int{14, 19}) {
		t.Fatalf("reentrancy PCs=%v, want [14 19]", ev[0].PCs)
	}
	// 同一路径上 CALL 返回值也未校验。
	if len(findRule(rep, RuleUncheckedCallRet)) != 1 {
		t.Fatalf("expected unchecked-call evidence on same path")
	}
}

func TestAnalyzeCheckedCallIsClean(t *testing.T) {
	rep := NewAnalyzer().Analyze(mustHex(t, sampleCheckedCall))
	t.Logf("input=%s status=%s findings=%d", sampleCheckedCall, rep.Status, len(rep.Findings))
	if rep.Status != StatusClean {
		t.Fatalf("status=%s, want CLEAN; findings=%v", rep.Status, rep.Findings)
	}
}

func TestAnalyzeUncheckedCall(t *testing.T) {
	rep := NewAnalyzer().Analyze(mustHex(t, sampleUncheckedCall))
	ev := findRule(rep, RuleUncheckedCallRet)
	t.Logf("input=%s status=%s evidence=%v", sampleUncheckedCall, rep.Status, ev)
	if len(ev) != 1 || !reflect.DeepEqual(ev[0].PCs, []int{14}) {
		t.Fatalf("unchecked-call evidence=%v, want PCs [14]", ev)
	}
}

func TestAnalyzePrivilegedGuard(t *testing.T) {
	unguarded := NewAnalyzer().Analyze(mustHex(t, sampleUnguardedSelfdestruct))
	t.Logf("input=%s status=%s evidence=%v", sampleUnguardedSelfdestruct, unguarded.Status, unguarded.Findings)
	if len(findRule(unguarded, RuleUnguardedPriv)) != 1 {
		t.Fatalf("unguarded SELFDESTRUCT not flagged")
	}
	guarded := NewAnalyzer().Analyze(mustHex(t, sampleGuardedSelfdestruct))
	t.Logf("input=%s status=%s (CALLER guard present)", sampleGuardedSelfdestruct, guarded.Status)
	if len(findRule(guarded, RuleUnguardedPriv)) != 0 {
		t.Fatalf("guarded SELFDESTRUCT should not be flagged: %v", guarded.Findings)
	}
}

func TestAnalyzeMalformedRejected(t *testing.T) {
	rep := NewAnalyzer().Analyze(mustHex(t, sampleMalformed))
	t.Logf("input=%s status=%s reason=%s", sampleMalformed, rep.Status, rep.Reject.Reason)
	if rep.Status != StatusRejected || rep.Reject == nil {
		t.Fatalf("malformed input must be REJECTED with reason, got %+v", rep)
	}
}

func TestAnalyzeDeterministic(t *testing.T) {
	code := mustHex(t, sampleReentrancy)
	first := NewAnalyzer().Analyze(code)
	for i := 0; i < 5; i++ {
		got := NewAnalyzer().Analyze(code)
		if !reflect.DeepEqual(first, got) {
			t.Fatalf("run %d differs:\nfirst=%+v\ngot=%+v", i, first, got)
		}
	}
	t.Logf("input=%s analyzed 6 times, identical report (hash=%s)", sampleReentrancy, first.CodeHash[:16])
}

func TestRulesetReproducibility(t *testing.T) {
	code := mustHex(t, sampleReentrancy)
	full := NewAnalyzer().Analyze(code)

	// 规则调整后 RulesetID 必须变化，但同规则集重复分析结论一致。
	custom := &Analyzer{Rules: []Rule{DefaultRules()[0]}}
	if custom.Analyze(code).RulesetID == full.RulesetID {
		t.Fatalf("ruleset ID should change when rules change")
	}
	a, b := custom.Analyze(code), custom.Analyze(code)
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("same ruleset + same input must reproduce identical report")
	}
	if len(findRule(a, RuleReentrancy)) != 1 || len(findRule(a, RuleUncheckedCallRet)) != 0 {
		t.Fatalf("custom ruleset should only apply reentrancy rule: %v", a.Findings)
	}
	t.Logf("full=%s custom=%s: 规则调整可按 RulesetID 区分复现", full.RulesetID, a.RulesetID)
}
