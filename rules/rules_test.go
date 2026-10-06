package rules

import (
	"testing"

	"github.com/highcumontoa/evm-bytecode-audit-go/bytecode"
	"github.com/highcumontoa/evm-bytecode-audit-go/opcodes"
)

func mustDecode(t *testing.T, code []byte) (*bytecode.DecodedContract, []bytecode.Block) {
	t.Helper()
	c, err := bytecode.Decode("t", code)
	if err != nil {
		t.Fatalf("unexpected rejection: %v", err)
	}
	return c, bytecode.SplitBlocks(c)
}

func b(ops ...byte) []byte { return ops }
func push1(v byte) []byte  { return []byte{byte(opcodes.PUSH1), v} }

func TestReentrancyRule(t *testing.T) {
	r := ReentrancyRule{}
	if r.ID() != RuleReentrancy || r.Version() == "" {
		t.Fatal("rule identity/version missing")
	}

	t.Run("hit_call_then_sstore", func(t *testing.T) {
		code := b(append(push1(0), push1(0)...)...)
		code = append(code, byte(opcodes.CALL), byte(opcodes.SSTORE), byte(opcodes.STOP))
		c, blocks := mustDecode(t, code)
		found := r.Check(c, blocks)
		t.Logf("input len=%d head=% x -> expect 1 reentrancy hit with call+sstore offsets", len(code), code[:min(8, len(code))])
		if len(found) != 1 {
			t.Fatalf("findings = %d, want 1", len(found))
		}
		f := found[0]
		if f.Severity != SeverityHigh || len(f.Evidence) != 1 {
			t.Fatalf("unexpected finding shape: %+v", f)
		}
		ev := f.Evidence[0]
		callOff := ev.Details["call_offset"].(int)
		sOff := ev.Details["sstore_offset"].(int)
		if callOff != 4 || sOff != 5 || code[callOff] != byte(opcodes.CALL) || code[sOff] != byte(opcodes.SSTORE) {
			t.Fatalf("evidence offsets do not verify against input: call=%d sstore=%d", callOff, sOff)
		}
		t.Logf("verdict basis: %s | evidence offsets %v verified against raw bytes", f.Message, ev.Offsets)
	})

	t.Run("no_hit_sstore_before_call", func(t *testing.T) {
		code := append(push1(0), byte(opcodes.SSTORE), byte(opcodes.PUSH1), 0, byte(opcodes.PUSH1), 0)
		code = append(code, byte(opcodes.CALL), byte(opcodes.STOP))
		c, blocks := mustDecode(t, code)
		if f := r.Check(c, blocks); len(f) != 0 {
			t.Fatalf("SSTORE before CALL must not hit, got %+v", f)
		}
		t.Logf("input=SSTORE then CALL -> no hit (update-before-call is safe ordering)")
	})

	t.Run("no_hit_staticcall", func(t *testing.T) {
		code := append(push1(0), byte(opcodes.STATICCALL), byte(opcodes.SSTORE), byte(opcodes.STOP))
		c, blocks := mustDecode(t, code)
		if f := r.Check(c, blocks); len(f) != 0 {
			t.Fatalf("STATICCALL cannot reenter mutably, got %+v", f)
		}
		t.Logf("input=STATICCALL then SSTORE -> no hit (read-only call excluded)")
	})
}

func TestUncheckedCallRule(t *testing.T) {
	r := UncheckedCallRule{}
	t.Run("hit_pop", func(t *testing.T) {
		code := append(push1(0), byte(opcodes.CALL), byte(opcodes.POP), byte(opcodes.STOP))
		c, blocks := mustDecode(t, code)
		found := r.Check(c, blocks)
		t.Logf("input=CALL,POP len=%d -> expect hit; offsets verifiable", len(code))
		if len(found) != 1 {
			t.Fatalf("findings = %d, want 1", len(found))
		}
		ev := found[0].Evidence[0]
		if ev.Offsets[0] != 2 || ev.Offsets[1] != 3 {
			t.Fatalf("evidence offsets = %v, want [2 3]", ev.Offsets)
		}
		if found[0].Evidence[0].Details["call_opcode"] != "CALL" {
			t.Fatalf("call opcode detail wrong")
		}
	})
	t.Run("no_hit_when_tested", func(t *testing.T) {
		// CALL ISZERO PUSH1 5 JUMPI ...  (failure branch tested)
		code := b(byte(opcodes.PUSH1), 0, byte(opcodes.CALL), byte(opcodes.ISZERO), byte(opcodes.PUSH1), 0x07, byte(opcodes.JUMPI), byte(opcodes.JUMPDEST), byte(opcodes.STOP))
		c, blocks := mustDecode(t, code)
		if f := r.Check(c, blocks); len(f) != 0 {
			t.Fatalf("tested call must not hit, got %+v", f)
		}
		t.Logf("input=CALL ISZERO JUMPI -> no hit (success bit is branched on)")
	})
	t.Run("delegatecall_covered", func(t *testing.T) {
		code := b(byte(opcodes.PUSH1), 0, byte(opcodes.DELEGATECALL), byte(opcodes.POP), byte(opcodes.STOP))
		c, blocks := mustDecode(t, code)
		found := r.Check(c, blocks)
		if len(found) != 1 || found[0].Evidence[0].Details["call_opcode"] != "DELEGATECALL" {
			t.Fatalf("DELEGATECALL/POP must hit, got %+v", found)
		}
		t.Logf("input=DELEGATECALL,POP -> hit (rule covers CALL/CALLCODE/DELEGATECALL)")
	})
}

func TestPrivilegedRule(t *testing.T) {
	r := UnprotectedPrivilegedRule{}
	t.Run("hit_no_guard", func(t *testing.T) {
		code := append(push1(0), byte(opcodes.SELFDESTRUCT))
		c, blocks := mustDecode(t, code)
		found := r.Check(c, blocks)
		t.Logf("input=PUSH1 0 SELFDESTRUCT len=%d -> expect unguarded hit", len(code))
		if len(found) != 1 {
			t.Fatalf("findings = %d, want 1", len(found))
		}
		if found[0].Severity != SeverityHigh {
			t.Fatalf("severity = %s, want high", found[0].Severity)
		}
	})
	t.Run("no_hit_caller_eq_guard", func(t *testing.T) {
		code := b(
			byte(opcodes.PUSH1), 0xAA,
			byte(opcodes.CALLER), byte(opcodes.EQ), byte(opcodes.ISZERO),
			byte(opcodes.PUSH1), 0x0b, byte(opcodes.JUMPI),
			byte(opcodes.PUSH1), 0x00, byte(opcodes.SELFDESTRUCT),
			byte(opcodes.JUMPDEST), byte(opcodes.STOP),
		)
		c, blocks := mustDecode(t, code)
		if f := r.Check(c, blocks); len(f) != 0 {
			t.Fatalf("guarded SELFDESTRUCT must not hit, got %+v", f)
		}
		t.Logf("input=owner-pattern CALLER EQ JUMPI SELFDESTRUCT -> no hit")
	})
	t.Run("caller_without_eq_still_hits", func(t *testing.T) {
		code := b(byte(opcodes.CALLER), byte(opcodes.POP), byte(opcodes.PUSH1), 0, byte(opcodes.SELFDESTRUCT))
		c, blocks := mustDecode(t, code)
		found := r.Check(c, blocks)
		if len(found) != 1 {
			t.Fatalf("CALLER without EQ is not a guard, findings=%d", len(found))
		}
		if found[0].Evidence[0].Details["missing_guard"] != "EQ" {
			t.Fatalf("missing_guard detail = %v", found[0].Evidence[0].Details["missing_guard"])
		}
		t.Logf("input=CALLER POP ... SELFDESTRUCT -> hit, missing EQ")
	})
}

func TestDeterminismAndOrder(t *testing.T) {
	code := b(
		byte(opcodes.PUSH1), 0, byte(opcodes.CALL), byte(opcodes.POP),
		byte(opcodes.PUSH1), 0, byte(opcodes.PUSH1), 0, byte(opcodes.CALL), byte(opcodes.SSTORE), byte(opcodes.STOP),
	)
	c, blocks := mustDecode(t, code)
	var first []Finding
	for i := 0; i < 50; i++ {
		got := []Finding{}
		for _, r := range DefaultRules() {
			got = append(got, r.Check(c, blocks)...)
		}
		if first == nil {
			first = got
			continue
		}
		if len(got) != len(first) {
			t.Fatalf("run %d finding count drift: %d vs %d", i, len(got), len(first))
		}
		for j := range got {
			if got[j].RuleID != first[j].RuleID || got[j].Message != first[j].Message {
				t.Fatalf("run %d finding %d drifted", i, j)
			}
		}
	}
	t.Logf("input=combo(len=%d) -> 50 reruns identical; order: %s, %s",
		len(code), first[0].RuleID, first[1].RuleID)
}

// ---- path-sensitive semantics (rule version 2.0.0) ----

func TestReentrancyRule_CrossBlockPath(t *testing.T) {
	r := ReentrancyRule{}
	// 0: PUSH1 0 CALL PUSH1 0x06 JUMP | 6: JUMPDEST SSTORE STOP
	code := b(
		byte(opcodes.PUSH1), 0x00,
		byte(opcodes.CALL),
		byte(opcodes.PUSH1), 0x06,
		byte(opcodes.JUMP),
		byte(opcodes.JUMPDEST), byte(opcodes.SSTORE), byte(opcodes.STOP),
	)
	c, blocks := mustDecode(t, code)
	found := r.Check(c, blocks)
	t.Logf("input=CALL;JUMP 6;JUMPDEST SSTORE len=%d -> expect 1 hit with cross-block witness path", len(code))
	if len(found) != 1 {
		t.Fatalf("findings = %d, want 1", len(found))
	}
	ev := found[0].Evidence[0]
	want := []int{2, 6, 7} // CALL, JUMPDEST, SSTORE in execution order
	if len(ev.Offsets) != len(want) {
		t.Fatalf("path offsets = %v, want %v", ev.Offsets, want)
	}
	for i, off := range want {
		if ev.Offsets[i] != off {
			t.Fatalf("path offsets = %v, want %v", ev.Offsets, want)
		}
	}
	// Every cited offset must index the expected opcode in the raw input.
	if code[ev.Offsets[0]] != byte(opcodes.CALL) ||
		code[ev.Offsets[1]] != byte(opcodes.JUMPDEST) ||
		code[ev.Offsets[2]] != byte(opcodes.SSTORE) {
		t.Fatalf("path offsets do not verify against raw bytes: %v", ev.Offsets)
	}
	t.Logf("verdict basis: %s | path %v verified against raw bytes", found[0].Message, ev.Offsets)
}

func TestReentrancyRule_NoReachableWriteNoHit(t *testing.T) {
	r := ReentrancyRule{}
	// 0: PUSH1 0 CALL STOP | 4: JUMPDEST SSTORE STOP  (dead segment)
	code := b(
		byte(opcodes.PUSH1), 0x00,
		byte(opcodes.CALL), byte(opcodes.STOP),
		byte(opcodes.JUMPDEST), byte(opcodes.SSTORE), byte(opcodes.STOP),
	)
	c, blocks := mustDecode(t, code)
	if f := r.Check(c, blocks); len(f) != 0 {
		t.Fatalf("SSTORE unreachable from the CALL must not hit, got %+v", f)
	}
	t.Logf("input=CALL STOP | dead JUMPDEST SSTORE -> no hit (no path from call to write)")
}

func TestReentrancyRule_LoopConverges(t *testing.T) {
	r := ReentrancyRule{}
	// 0: JUMPDEST PUSH1 0 CALL PUSH1 0x0a JUMPI
	// 7: PUSH1 0 JUMP (back edge to 0)
	// 10: JUMPDEST SSTORE STOP
	code := b(
		byte(opcodes.JUMPDEST),
		byte(opcodes.PUSH1), 0x00,
		byte(opcodes.CALL),
		byte(opcodes.PUSH1), 0x0a,
		byte(opcodes.JUMPI),
		byte(opcodes.PUSH1), 0x00,
		byte(opcodes.JUMP),
		byte(opcodes.JUMPDEST), byte(opcodes.SSTORE), byte(opcodes.STOP),
	)
	c, blocks := mustDecode(t, code)
	first := r.Check(c, blocks)
	if len(first) != 1 {
		t.Fatalf("findings = %d, want exactly 1 despite the loop", len(first))
	}
	for i := 0; i < 20; i++ {
		got := r.Check(c, blocks)
		if len(got) != 1 || got[0].Message != first[0].Message {
			t.Fatalf("run %d drifted under a loop: %+v", i, got)
		}
	}
	t.Logf("input=loop back-edge before SSTORE -> exactly 1 hit, stable over 20 reruns; path=%v",
		first[0].Evidence[0].Offsets)
}

func TestPrivilegedRule_BranchBypass(t *testing.T) {
	r := UnprotectedPrivilegedRule{}
	// 0: PUSH1 1 PUSH1 0x08 JUMPI          ; conditional branch
	// 5: PUSH1 0 SELFDESTRUCT              ; unguarded fall-through
	// 8: JUMPDEST PUSH1 0xAA CALLER EQ ISZERO PUSH1 0x14 JUMPI
	// 17: PUSH1 0 SELFDESTRUCT             ; guarded
	// 20: JUMPDEST STOP
	code := b(
		byte(opcodes.PUSH1), 0x01,
		byte(opcodes.PUSH1), 0x08,
		byte(opcodes.JUMPI),
		byte(opcodes.PUSH1), 0x00,
		byte(opcodes.SELFDESTRUCT),
		byte(opcodes.JUMPDEST),
		byte(opcodes.PUSH1), 0xAA,
		byte(opcodes.CALLER), byte(opcodes.EQ), byte(opcodes.ISZERO),
		byte(opcodes.PUSH1), 0x14,
		byte(opcodes.JUMPI),
		byte(opcodes.PUSH1), 0x00,
		byte(opcodes.SELFDESTRUCT),
		byte(opcodes.JUMPDEST), byte(opcodes.STOP),
	)
	c, blocks := mustDecode(t, code)
	found := r.Check(c, blocks)
	t.Logf("input=branch around guard len=%d -> expect exactly 1 hit (offset 7), guarded twin not reported", len(code))
	if len(found) != 1 {
		t.Fatalf("findings = %d, want 1 (only the bypassing SELFDESTRUCT)", len(found))
	}
	ev := found[0].Evidence[0]
	if ev.Details["privileged_offset"].(int) != 7 {
		t.Fatalf("flagged offset = %v, want 7", ev.Details["privileged_offset"])
	}
	// Witness path: entry block 0 -> fall-through block at 5 -> SELFDESTRUCT 7.
	want := []int{0, 5, 7}
	if len(ev.Offsets) != len(want) {
		t.Fatalf("bypass path = %v, want %v", ev.Offsets, want)
	}
	for i := range want {
		if ev.Offsets[i] != want[i] {
			t.Fatalf("bypass path = %v, want %v", ev.Offsets, want)
		}
	}
	if code[7] != byte(opcodes.SELFDESTRUCT) {
		t.Fatalf("offset 7 is not the SELFDESTRUCT in the raw input")
	}
	t.Logf("verdict basis: %s | bypass path %v verified", found[0].Message, ev.Offsets)
}

func TestPrivilegedRule_GuardInEarlierBlockProtects(t *testing.T) {
	r := UnprotectedPrivilegedRule{}
	// 0: PUSH1 0xAA CALLER EQ ISZERO PUSH1 0x0b JUMPI
	// 8: PUSH1 0x0d JUMP | 11: JUMPDEST STOP | 13: JUMPDEST PUSH1 0 SELFDESTRUCT
	code := b(
		byte(opcodes.PUSH1), 0xAA,
		byte(opcodes.CALLER), byte(opcodes.EQ), byte(opcodes.ISZERO),
		byte(opcodes.PUSH1), 0x0b,
		byte(opcodes.JUMPI),
		byte(opcodes.PUSH1), 0x0d,
		byte(opcodes.JUMP),
		byte(opcodes.JUMPDEST), byte(opcodes.STOP),
		byte(opcodes.JUMPDEST),
		byte(opcodes.PUSH1), 0x00,
		byte(opcodes.SELFDESTRUCT),
	)
	c, blocks := mustDecode(t, code)
	if f := r.Check(c, blocks); len(f) != 0 {
		t.Fatalf("guard in a dominating earlier block must protect, got %+v", f)
	}
	t.Logf("input=guard block -> JUMP -> SELFDESTRUCT block -> no hit (all paths pass the guard)")
}

func TestPrivilegedRule_LoopConverges(t *testing.T) {
	r := UnprotectedPrivilegedRule{}
	// 0: JUMPDEST PUSH1 0 JUMPI (back edge to 0) | 4: PUSH1 0 SELFDESTRUCT
	code := b(
		byte(opcodes.JUMPDEST),
		byte(opcodes.PUSH1), 0x00,
		byte(opcodes.JUMPI),
		byte(opcodes.PUSH1), 0x00,
		byte(opcodes.SELFDESTRUCT),
	)
	c, blocks := mustDecode(t, code)
	first := r.Check(c, blocks)
	if len(first) != 1 {
		t.Fatalf("findings = %d, want exactly 1 despite the loop", len(first))
	}
	for i := 0; i < 20; i++ {
		got := r.Check(c, blocks)
		if len(got) != 1 || got[0].Message != first[0].Message {
			t.Fatalf("run %d drifted under a loop: %+v", i, got)
		}
	}
	t.Logf("input=loop back-edge, unguarded SELFDESTRUCT -> exactly 1 hit, stable over 20 reruns")
}
