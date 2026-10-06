package audit_test

import (
	"testing"
	"time"

	"github.com/highcumontoa/evm-bytecode-audit-go/audit"
	"github.com/highcumontoa/evm-bytecode-audit-go/opcodes"
	"github.com/highcumontoa/evm-bytecode-audit-go/rules"
)

// buildWideContract builds a contract with `blocks` basic blocks, every one
// containing an external CALL and a conditional back edge to the entry
// block, plus a final block holding SSTORE;STOP. It exercises many
// instructions, many branches and many loops at once.
func buildWideContract(blocks int) []byte {
	const blkLen = 7 // JUMPDEST PUSH1 0 CALL PUSH1 0 JUMPI
	code := make([]byte, 0, blocks*blkLen+3)
	for i := 0; i < blocks; i++ {
		code = append(code,
			byte(opcodes.JUMPDEST),
			byte(opcodes.PUSH1), 0x00,
			byte(opcodes.CALL),
			byte(opcodes.PUSH1), 0x00, // back edge to the entry JUMPDEST
			byte(opcodes.JUMPI),
		)
	}
	code = append(code, byte(opcodes.JUMPDEST), byte(opcodes.SSTORE), byte(opcodes.STOP))
	return code
}

func TestAnalyzer_LargeLoopyContractConcludes(t *testing.T) {
	const blocks = 400
	code := buildWideContract(blocks)
	a := audit.NewAnalyzer(nil)

	start := time.Now()
	r := a.Analyze("wide_loopy", code)
	elapsed := time.Since(start)

	if r.Status != audit.StatusOK {
		t.Fatalf("status = %s (%s)", r.Status, r.RejectDetail)
	}
	// Every CALL can loop back and eventually reach the final SSTORE.
	if len(r.Findings) != blocks {
		t.Fatalf("findings = %d, want %d (one per CALL)", len(r.Findings), blocks)
	}
	for _, f := range r.Findings {
		if f.RuleID != rules.RuleReentrancy {
			t.Fatalf("unexpected rule %s", f.RuleID)
		}
	}
	// Generous ceiling: the algorithms are O(blocks x edges); anything
	// close to this bound indicates non-convergent expansion.
	if elapsed > 10*time.Second {
		t.Fatalf("analysis took %v, want well under 10s", elapsed)
	}
	// Determinism on the same large input.
	r2 := a.Analyze("wide_loopy", code)
	if len(r2.Findings) != len(r.Findings) || r2.Findings[0].Message != r.Findings[0].Message {
		t.Fatalf("repeated analysis of a large contract drifted")
	}
	t.Logf("input=%d blocks x (CALL+back edge), len=%d sha=%s -> %d findings in %v; rerun identical",
		blocks, r.ByteLen, shortHash(r.InputHash), len(r.Findings), elapsed)
}

func TestBatch_LargeContractConcurrentEqualsSerial(t *testing.T) {
	code := buildWideContract(120)
	inputs := []audit.ContractInput{
		{Name: "wide_a", Code: code},
		{Name: "wide_b", Code: code},
	}
	serial := audit.NewAnalyzer(nil).Analyze("wide_a", code)
	for _, workers := range []int{1, 2, 8} {
		got := audit.NewBatch(audit.NewAnalyzer(nil), nil, 0, workers).Run(inputs)
		if len(got) != 2 {
			t.Fatalf("workers=%d: %d reports", workers, len(got))
		}
		if len(got[0].Findings) != len(serial.Findings) {
			t.Fatalf("workers=%d: concurrent findings drift from serial", workers)
		}
	}
	t.Logf("input=2x(%d blocks) x 3 worker counts -> findings match serial exactly", 120)
}
