package audit_test

import (
	"encoding/json"
	"testing"

	"github.com/highcumontoa/evm-bytecode-audit-go/audit"
	"github.com/highcumontoa/evm-bytecode-audit-go/bytecode"
	"github.com/highcumontoa/evm-bytecode-audit-go/rules"
	"github.com/highcumontoa/evm-bytecode-audit-go/samples"
)

// summary logs the input digest and the decision basis, as required.
func summary(t *testing.T, r *audit.Report) {
	t.Helper()
	kinds := ""
	for _, f := range r.Findings {
		kinds += " " + string(f.RuleID)
	}
	t.Logf("input=%s len=%d sha=%s -> status=%s reject=%s findings:[%s]",
		r.Name, r.ByteLen, shortHash(r.InputHash), r.Status, r.RejectKind, kinds)
}

func shortHash(h string) string {
	if len(h) <= 12 {
		return h
	}
	return h[:12] + "..."
}

func TestAnalyzer_RepeatedAnalysisIsIdentical(t *testing.T) {
	a := audit.NewAnalyzer(nil)
	for _, s := range samples.All() {
		r1 := a.Analyze(s.Name, s.Code)
		r2 := a.Analyze(s.Name, s.Code)
		j1, _ := json.Marshal(r1)
		j2, _ := json.Marshal(r2)
		if string(j1) != string(j2) {
			t.Fatalf("non-deterministic report for %s", s.Name)
		}
		if r1.InputHash != audit.HashInput(s.Code) {
			t.Fatalf("hash mismatch for %s", s.Name)
		}
		summary(t, r1)
	}
}

func TestAnalyzer_ExpectedSampleVerdicts(t *testing.T) {
	a := audit.NewAnalyzer(nil)
	cases := []struct {
		name       string
		status     audit.Status
		rejectKind bytecode.RejectKind
		findings   []rules.RuleID
	}{
		{"benign_empty_stop", audit.StatusOK, "", nil},
		{"benign_valid_jump", audit.StatusOK, "", nil},
		{"benign_guarded_selfdestruct", audit.StatusOK, "", nil},
		{"benign_guarded_cross_block", audit.StatusOK, "", nil},
		{"benign_call_then_halt_dead_sstore", audit.StatusOK, "", nil},
		{"risky_reentrancy", audit.StatusOK, "", []rules.RuleID{rules.RuleReentrancy}},
		{"risky_reentrancy_cross_block", audit.StatusOK, "", []rules.RuleID{rules.RuleReentrancy}},
		{"risky_reentrancy_via_loop", audit.StatusOK, "", []rules.RuleID{rules.RuleReentrancy}},
		{"risky_guard_bypass_branch", audit.StatusOK, "", []rules.RuleID{rules.RuleUnprotectedPrivileged}},
		{"risky_unchecked_call", audit.StatusOK, "", []rules.RuleID{rules.RuleUncheckedCall}},
		{"risky_unprotected_selfdestruct", audit.StatusOK, "", []rules.RuleID{rules.RuleUnprotectedPrivileged}},
		{"risky_combo", audit.StatusOK, "", []rules.RuleID{rules.RuleReentrancy, rules.RuleReentrancy, rules.RuleUncheckedCall}},
		{"malformed_empty", audit.StatusRejected, bytecode.RejectEmpty, nil},
		{"malformed_invalid_opcode", audit.StatusRejected, bytecode.RejectInvalidOpcode, nil},
		{"malformed_truncated_push", audit.StatusRejected, bytecode.RejectTruncatedImmediate, nil},
		{"malformed_jump_out_of_bounds", audit.StatusRejected, bytecode.RejectJumpOutOfBounds, nil},
		{"malformed_jump_not_jumpdest", audit.StatusRejected, bytecode.RejectJumpNotDest, nil},
		{"malformed_jump_loop_no_halt", audit.StatusRejected, bytecode.RejectNoHaltingPath, nil},
	}
	byName := map[string]samples.Contract{}
	for _, s := range samples.All() {
		byName[s.Name] = s
	}
	for _, want := range cases {
		s := byName[want.name]
		r := a.Analyze(s.Name, s.Code)
		summary(t, r)
		if r.Status != want.status {
			t.Fatalf("%s: status %s want %s (%s)", want.name, r.Status, want.status, r.RejectDetail)
		}
		if r.RejectKind != want.rejectKind {
			t.Fatalf("%s: reject %q want %q", want.name, r.RejectKind, want.rejectKind)
		}
		if len(r.Findings) != len(want.findings) {
			t.Fatalf("%s: %d findings want %d (%v)", want.name, len(r.Findings), len(want.findings), r.Findings)
		}
		for i, id := range want.findings {
			if r.Findings[i].RuleID != id {
				t.Fatalf("%s: finding %d = %s want %s", want.name, i, r.Findings[i].RuleID, id)
			}
			if len(r.Findings[i].Evidence) == 0 {
				t.Fatalf("%s: finding %s carries no evidence", want.name, id)
			}
		}
		if len(r.RuleVersions) != 3 {
			t.Fatalf("%s: rule versions not recorded", want.name)
		}
	}
}

func TestAnalyzer_RuleVersionChangeIsReproducible(t *testing.T) {
	// The report pins rule versions; an old report can be re-derived by
	// running the analyzer whose rule set carries the same versions.
	s := samples.All()
	var guarded samples.Contract
	for _, c := range s {
		if c.Name == "benign_guarded_selfdestruct" {
			guarded = c
		}
	}
	a := audit.NewAnalyzer([]rules.Rule{rules.UnprotectedPrivilegedRule{}})
	r := a.Analyze(guarded.Name, guarded.Code)
	if len(r.RuleVersions) != 1 || r.RuleVersions[0].Version != rules.UnprotectedPrivilegedRuleVersion {
		t.Fatalf("pinned versions wrong: %+v", r.RuleVersions)
	}
	t.Logf("report pins %s@%s for input sha=%s -> historical re-run is possible",
		r.RuleVersions[0].RuleID, r.RuleVersions[0].Version, shortHash(r.InputHash))
}

// TestAnalyzer_NoHaltingPathRegression pins the regression: an input that
// decodes cleanly and contains no risky opcodes used to be reported as a
// clean contract (status ok, zero findings) even though no execution path
// can terminate normally. It must now be explicitly rejected, with a reason
// distinct from every pre-existing reject kind.
func TestAnalyzer_NoHaltingPathRegression(t *testing.T) {
	a := audit.NewAnalyzer(nil)
	// JUMPDEST PUSH1 0 JUMP: an unconditional jump loop.
	code := []byte{0x5b, 0x60, 0x00, 0x56}
	r := a.Analyze("regression_jump_loop", code)
	summary(t, r)
	if r.Status != audit.StatusRejected {
		t.Fatalf("status = %s, want rejected (previously reported clean)", r.Status)
	}
	if r.RejectKind != bytecode.RejectNoHaltingPath {
		t.Fatalf("reject kind = %q, want %q", r.RejectKind, bytecode.RejectNoHaltingPath)
	}
	for _, other := range []bytecode.RejectKind{
		bytecode.RejectEmpty, bytecode.RejectInvalidOpcode,
		bytecode.RejectTruncatedImmediate, bytecode.RejectJumpOutOfBounds,
		bytecode.RejectJumpNotDest,
	} {
		if r.RejectKind == other {
			t.Fatalf("no_halting_path collapsed into existing kind %q", other)
		}
	}
	if len(r.Findings) != 0 {
		t.Fatalf("rejected input must carry no findings, got %d", len(r.Findings))
	}
	t.Logf("verdict basis: %s -> %s (distinct from all pre-existing reject kinds)", r.RejectKind, r.RejectDetail)
}
