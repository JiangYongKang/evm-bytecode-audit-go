package bytecode

import (
	"errors"
	"testing"

	"github.com/highcumontoa/evm-bytecode-audit-go/opcodes"
)

func TestBuildCFG_Edges(t *testing.T) {
	// 0: PUSH1 0 CALL PUSH1 0x06 JUMP | 6: JUMPDEST SSTORE STOP
	code := []byte{
		byte(opcodes.PUSH1), 0x00,
		byte(opcodes.CALL),
		byte(opcodes.PUSH1), 0x06,
		byte(opcodes.JUMP),
		byte(opcodes.JUMPDEST), byte(opcodes.SSTORE), byte(opcodes.STOP),
	}
	c, err := Decode("cfg", code)
	if err != nil {
		t.Fatal(err)
	}
	cfg := BuildCFG(c, SplitBlocks(c))
	summarize(t, "cfg", code, "block0 --JUMP 6--> block1; block1 halts")
	if len(cfg.Blocks) != 2 {
		t.Fatalf("blocks = %d, want 2", len(cfg.Blocks))
	}
	if len(cfg.Succ[0]) != 1 || cfg.Succ[0][0] != 1 {
		t.Fatalf("Succ[0] = %v, want [1]", cfg.Succ[0])
	}
	if len(cfg.Succ[1]) != 0 {
		t.Fatalf("Succ[1] = %v, want [] (STOP)", cfg.Succ[1])
	}
	if cfg.HasDynamicJump[0] || cfg.HasDynamicJump[1] {
		t.Fatalf("no dynamic jumps expected: %v", cfg.HasDynamicJump)
	}
	// Determinism: rebuilding yields identical edges.
	again := BuildCFG(c, SplitBlocks(c))
	for i := range cfg.Succ {
		if len(cfg.Succ[i]) != len(again.Succ[i]) {
			t.Fatalf("CFG construction not deterministic at block %d", i)
		}
	}
}

func TestBuildCFG_ConditionalAndDynamic(t *testing.T) {
	// 0: PUSH1 0x04 JUMPI          ; static target 4 + fall-through to 3
	// 3: JUMP (dynamic) | 4: JUMPDEST STOP
	code := []byte{
		byte(opcodes.PUSH1), 0x04,
		byte(opcodes.JUMPI),
		byte(opcodes.JUMP), // dynamic target: no preceding PUSH in this block
		byte(opcodes.JUMPDEST), byte(opcodes.STOP),
	}
	c, err := Decode("cfg2", code)
	if err != nil {
		t.Fatal(err)
	}
	cfg := BuildCFG(c, SplitBlocks(c))
	summarize(t, "cfg2", code, "JUMPI keeps fall-through+target edges; dynamic JUMP flagged, not rejected")
	if len(cfg.Blocks) != 3 {
		t.Fatalf("blocks = %d, want 3", len(cfg.Blocks))
	}
	if len(cfg.Succ[0]) != 2 || cfg.Succ[0][0] != 1 || cfg.Succ[0][1] != 2 {
		t.Fatalf("Succ[0] = %v, want [1 2] (fall-through then target, offset order)", cfg.Succ[0])
	}
	if !cfg.HasDynamicJump[1] {
		t.Fatalf("block 1 ends in a dynamic JUMP and must be flagged")
	}
	if len(cfg.Succ[1]) != 0 {
		t.Fatalf("dynamic JUMP contributes no static edges, got %v", cfg.Succ[1])
	}
}

func TestDecode_NoHaltingPathRejected(t *testing.T) {
	// JUMPDEST PUSH1 0 JUMP: an unconditional jump loop. Decodes cleanly
	// under every previous check but no execution path terminates normally.
	code := []byte{byte(opcodes.JUMPDEST), byte(opcodes.PUSH1), 0x00, byte(opcodes.JUMP)}
	summarize(t, "jump_loop", code, "infinite static jump loop -> no_halting_path")
	_, err := Decode("jump_loop", code)
	rejectAs(t, err, RejectNoHaltingPath, -1)
}

func TestDecode_NoHaltingPathDistinguishable(t *testing.T) {
	// The new reason must not collapse into any existing bucket.
	loop := []byte{byte(opcodes.JUMPDEST), byte(opcodes.PUSH1), 0x00, byte(opcodes.JUMP)}
	others := [][]byte{
		nil,                         // empty
		{0x0e},                      // invalid opcode
		{byte(opcodes.PUSH2), 0x00}, // truncated
		{byte(opcodes.PUSH1), 0x09, byte(opcodes.JUMP)},       // oob
		{byte(opcodes.PUSH1), 0x00, byte(opcodes.JUMP), 0x00}, // not jumpdest
	}
	seen := map[RejectKind]bool{}
	_, err := Decode("loop", loop)
	var rj *RejectError
	if !errors.As(err, &rj) {
		t.Fatalf("loop: not a RejectError: %v", err)
	}
	seen[rj.Kind] = true
	for i, code := range others {
		_, err := Decode("other", code)
		var rj2 *RejectError
		if !errors.As(err, &rj2) {
			t.Fatalf("case %d: not a RejectError: %v", i, err)
		}
		seen[rj2.Kind] = true
	}
	if !seen[RejectNoHaltingPath] || len(seen) != 6 {
		t.Fatalf("reject kinds collapsed: %v", seen)
	}
	t.Logf("input=jump loop + 5 classic malformed shapes -> 6 distinct reject kinds: %v", seen)
}

func TestDecode_HaltingPathAccepts(t *testing.T) {
	cases := []struct {
		name string
		code []byte
		why  string
	}{
		{"stop", []byte{byte(opcodes.STOP)}, "STOP terminates"},
		{"selfdestruct", []byte{byte(opcodes.PUSH1), 0, byte(opcodes.SELFDESTRUCT)}, "SELFDESTRUCT terminates"},
		{"fall_off_end", []byte{byte(opcodes.PUSH1), 0, byte(opcodes.POP)}, "running off the end is an implicit STOP"},
		{"dynamic_jump_benefit_of_doubt", []byte{byte(opcodes.JUMP)}, "dynamic target: termination undecidable, not rejected"},
		{"loop_with_exit", []byte{
			byte(opcodes.JUMPDEST), byte(opcodes.PUSH1), 0x07, byte(opcodes.JUMPI),
			byte(opcodes.PUSH1), 0x00, byte(opcodes.JUMP),
			byte(opcodes.JUMPDEST), byte(opcodes.STOP),
		}, "loop with a static exit edge reaches STOP"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			summarize(t, tc.name, tc.code, tc.why)
			if _, err := Decode(tc.name, tc.code); err != nil {
				t.Fatalf("rejected: %v", err)
			}
		})
	}
}
