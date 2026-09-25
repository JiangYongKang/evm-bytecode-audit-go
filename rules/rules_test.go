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
