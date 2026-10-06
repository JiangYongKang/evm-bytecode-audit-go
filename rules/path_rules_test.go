package rules

import (
	"testing"

	"github.com/highcumontoa/evm-bytecode-audit-go/opcodes"
)

// logFinding logs the per-finding decision basis, as required.
func logFinding(t *testing.T, f Finding) {
	t.Helper()
	for _, ev := range f.Evidence {
		t.Logf("verdict basis: %s | path offsets %v blocks %v", f.Message, ev.Offsets, ev.Details["path_blocks"])
	}
}

func TestReentrancyRule_CrossBlockDetour(t *testing.T) {
	// 0: PUSH1 0 2: CALL 3: PUSH1 6 5: JUMP(->6)
	// 6: JUMPDEST 7: PUSH1 11 9: JUMP(->11) 10: STOP
	// 11: JUMPDEST 12: SSTORE 13: STOP
	code := b(
		byte(opcodes.PUSH1), 0x00,
		byte(opcodes.CALL),
		byte(opcodes.PUSH1), 0x06,
		byte(opcodes.JUMP),
		byte(opcodes.JUMPDEST),
		byte(opcodes.PUSH1), 0x0b,
		byte(opcodes.JUMP),
		byte(opcodes.STOP),
		byte(opcodes.JUMPDEST), byte(opcodes.SSTORE), byte(opcodes.STOP),
	)
	c, blocks := mustDecode(t, code)
	found := ReentrancyRule{}.Check(c, blocks)
	t.Logf("input len=%d: CALL detours through two jumped blocks before SSTORE", len(code))
	if len(found) != 1 {
		t.Fatalf("findings = %d, want 1", len(found))
	}
	logFinding(t, found[0])
	ev := found[0].Evidence[0]
	want := []int{2, 6, 11, 12} // execution order: call, detour blocks, write
	if len(ev.Offsets) != len(want) {
		t.Fatalf("path offsets = %v, want %v", ev.Offsets, want)
	}
	for i, off := range want {
		if ev.Offsets[i] != off {
			t.Fatalf("path offsets = %v, want %v", ev.Offsets, want)
		}
	}
	// Verify every cited offset against the raw bytes.
	if code[2] != byte(opcodes.CALL) || code[6] != byte(opcodes.JUMPDEST) ||
		code[11] != byte(opcodes.JUMPDEST) || code[12] != byte(opcodes.SSTORE) {
		t.Fatalf("path offsets do not verify against raw bytecode")
	}
}

func TestReentrancyRule_BranchMerge(t *testing.T) {
	// 0: PUSH1 8 2: PUSH1 0 4: CALL 5: JUMPI(->8) 6: PUSH1 0 (fallthrough)
	// 8: JUMPDEST 9: SSTORE 10: STOP
	// Both branches merge at the write block: the write after the merge
	// must still be attributed to the call.
	code := b(
		byte(opcodes.PUSH1), 0x08,
		byte(opcodes.PUSH1), 0x00,
		byte(opcodes.CALL), byte(opcodes.JUMPI),
		byte(opcodes.PUSH1), 0x00,
		byte(opcodes.JUMPDEST), byte(opcodes.SSTORE), byte(opcodes.STOP),
	)
	c, blocks := mustDecode(t, code)
	found := ReentrancyRule{}.Check(c, blocks)
	t.Logf("input len=%d: branches after CALL merge at the SSTORE block", len(code))
	if len(found) != 1 {
		t.Fatalf("findings = %d, want 1 (write after merge)", len(found))
	}
	logFinding(t, found[0])
	if got := found[0].Evidence[0].Details["sstore_offset"]; got != 9 {
		t.Fatalf("sstore_offset = %v, want 9", got)
	}
}

func TestReentrancyRule_NoHitWhenPathsHalt(t *testing.T) {
	// 0: PUSH1 0 2: CALL 3: PUSH1 7 5: JUMPI(->7) 6: STOP
	// 7: JUMPDEST 8: STOP 9: SSTORE (unreachable block)
	code := b(
		byte(opcodes.PUSH1), 0x00,
		byte(opcodes.CALL),
		byte(opcodes.PUSH1), 0x07,
		byte(opcodes.JUMPI), byte(opcodes.STOP),
		byte(opcodes.JUMPDEST), byte(opcodes.STOP),
		byte(opcodes.SSTORE),
	)
	c, blocks := mustDecode(t, code)
	found := ReentrancyRule{}.Check(c, blocks)
	t.Logf("input len=%d: every path after CALL halts; SSTORE is unreachable", len(code))
	if len(found) != 0 {
		t.Fatalf("no reachable write must not hit, got %+v", found)
	}
	t.Logf("verdict basis: no path from CALL(offset 2) reaches SSTORE(offset 9) -> clean")
}

func TestReentrancyRule_LoopBackEdgeConverges(t *testing.T) {
	// 0: JUMPDEST 1: SSTORE 2: PUSH1 0 4: CALL 5: PUSH1 0 7: JUMPI(->0) 8: STOP
	// The SSTORE sits BEFORE the call inside a loop: the back edge makes it
	// reachable after the call. The search must terminate and report once.
	code := b(
		byte(opcodes.JUMPDEST), byte(opcodes.SSTORE),
		byte(opcodes.PUSH1), 0x00,
		byte(opcodes.CALL),
		byte(opcodes.PUSH1), 0x00,
		byte(opcodes.JUMPI), byte(opcodes.STOP),
	)
	c, blocks := mustDecode(t, code)
	found := ReentrancyRule{}.Check(c, blocks)
	t.Logf("input len=%d: loop back edge makes pre-call SSTORE reachable post-call", len(code))
	if len(found) != 1 {
		t.Fatalf("findings = %d, want exactly 1 (loop must converge, not duplicate)", len(found))
	}
	logFinding(t, found[0])
	if got := found[0].Evidence[0].Details["sstore_offset"]; got != 1 {
		t.Fatalf("sstore_offset = %v, want 1", got)
	}
}

func TestPrivilegedRule_BranchBypass(t *testing.T) {
	// 0: PUSH1 7 2: JUMPI(->7) 3: PUSH1 0 5: SELFDESTRUCT 6: STOP
	// 7: JUMPDEST 8: PUSH1 0xAA 10: CALLER 11: EQ 12: ISZERO
	// 13: PUSH1 19 15: JUMPI(->19) 16: PUSH1 0 18: SELFDESTRUCT
	// 19: JUMPDEST 20: STOP
	code := b(
		byte(opcodes.PUSH1), 0x07, byte(opcodes.JUMPI),
		byte(opcodes.PUSH1), 0x00, byte(opcodes.SELFDESTRUCT), byte(opcodes.STOP),
		byte(opcodes.JUMPDEST),
		byte(opcodes.PUSH1), 0xAA,
		byte(opcodes.CALLER), byte(opcodes.EQ), byte(opcodes.ISZERO),
		byte(opcodes.PUSH1), 0x13, byte(opcodes.JUMPI),
		byte(opcodes.PUSH1), 0x00, byte(opcodes.SELFDESTRUCT),
		byte(opcodes.JUMPDEST), byte(opcodes.STOP),
	)
	c, blocks := mustDecode(t, code)
	found := UnprotectedPrivilegedRule{}.Check(c, blocks)
	t.Logf("input len=%d: guard lives on the taken branch; fall-through bypasses it", len(code))
	if len(found) != 1 {
		t.Fatalf("findings = %d, want 1 (only the bypassing SELFDESTRUCT)", len(found))
	}
	logFinding(t, found[0])
	ev := found[0].Evidence[0]
	if got := ev.Details["privileged_offset"]; got != 5 {
		t.Fatalf("flagged offset = %v, want 5 (the guarded one at 18 must not be flagged)", got)
	}
	want := []int{0, 3, 5} // entry, bypass block, SELFDESTRUCT
	if len(ev.Offsets) != len(want) {
		t.Fatalf("witness offsets = %v, want %v", ev.Offsets, want)
	}
	for i := range want {
		if ev.Offsets[i] != want[i] {
			t.Fatalf("witness offsets = %v, want %v", ev.Offsets, want)
		}
	}
	if code[5] != byte(opcodes.SELFDESTRUCT) {
		t.Fatalf("witness offset 5 does not verify against raw bytecode")
	}
}

func TestPrivilegedRule_LoopConverges(t *testing.T) {
	// Unguarded SELFDESTRUCT inside a reachable loop: exactly one finding.
	// 0: JUMPDEST 1: PUSH1 8 3: JUMPI(->8) 4: PUSH1 0 6: SELFDESTRUCT
	// 7: STOP 8: JUMPDEST 9: PUSH1 0 11: JUMP(->0)
	code := b(
		byte(opcodes.JUMPDEST),
		byte(opcodes.PUSH1), 0x08, byte(opcodes.JUMPI),
		byte(opcodes.PUSH1), 0x00, byte(opcodes.SELFDESTRUCT),
		byte(opcodes.STOP),
		byte(opcodes.JUMPDEST),
		byte(opcodes.PUSH1), 0x00, byte(opcodes.JUMP),
	)
	c, blocks := mustDecode(t, code)
	found := UnprotectedPrivilegedRule{}.Check(c, blocks)
	t.Logf("input len=%d: back edge to loop head; unguarded SELFDESTRUCT on one path", len(code))
	if len(found) != 1 {
		t.Fatalf("findings = %d, want exactly 1 (fixpoint must converge)", len(found))
	}
	logFinding(t, found[0])
	if got := found[0].Evidence[0].Details["privileged_offset"]; got != 6 {
		t.Fatalf("flagged offset = %v, want 6", got)
	}
}

func TestPrivilegedRule_GuardedLoopNoHit(t *testing.T) {
	// Guard in the loop head dominates the SELFDESTRUCT on every path:
	// 0: JUMPDEST 1: PUSH1 0xAA 3: CALLER 4: EQ 5: ISZERO
	// 6: PUSH1 13 8: JUMPI(->13) 9: PUSH1 0 11: SELFDESTRUCT
	// 12: STOP 13: JUMPDEST 14: PUSH1 0 16: JUMP(->0)
	code := b(
		byte(opcodes.JUMPDEST),
		byte(opcodes.PUSH1), 0xAA,
		byte(opcodes.CALLER), byte(opcodes.EQ), byte(opcodes.ISZERO),
		byte(opcodes.PUSH1), 0x0d, byte(opcodes.JUMPI),
		byte(opcodes.PUSH1), 0x00, byte(opcodes.SELFDESTRUCT),
		byte(opcodes.STOP),
		byte(opcodes.JUMPDEST),
		byte(opcodes.PUSH1), 0x00, byte(opcodes.JUMP),
	)
	c, blocks := mustDecode(t, code)
	found := UnprotectedPrivilegedRule{}.Check(c, blocks)
	t.Logf("input len=%d: guard in loop head, back edge to entry; must converge to guarded", len(code))
	if len(found) != 0 {
		t.Fatalf("guard dominating via loop head must not hit, got %+v", found)
	}
	t.Logf("verdict basis: every path to SELFDESTRUCT(offset 11) crosses CALLER/EQ in block 0 -> guarded")
}
