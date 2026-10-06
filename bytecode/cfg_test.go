package bytecode

import (
	"errors"
	"testing"

	"github.com/highcumontoa/evm-bytecode-audit-go/opcodes"
)

func decodeAndSplit(t *testing.T, name string, code []byte) (*DecodedContract, []Block) {
	t.Helper()
	c, err := Decode(name, code)
	if err != nil {
		t.Fatalf("unexpected rejection: %v", err)
	}
	return c, SplitBlocks(c)
}

func TestBuildCFG_Successors(t *testing.T) {
	// 0: PUSH1 6 2: JUMPI(->6) 3: PUSH1 0 5: SELFDESTRUCT
	// 6: JUMPDEST 7: STOP
	code := []byte{
		byte(opcodes.PUSH1), 0x06, byte(opcodes.JUMPI),
		byte(opcodes.PUSH1), 0x00, byte(opcodes.SELFDESTRUCT),
		byte(opcodes.JUMPDEST), byte(opcodes.STOP),
	}
	c, blocks := decodeAndSplit(t, "cfg", code)
	cfg := BuildCFG(c, blocks)
	summarize(t, "cfg", code, "JUMPI has static-target + fall-through successors; halts have none")
	if len(cfg.Blocks) != 3 {
		t.Fatalf("blocks = %d, want 3", len(cfg.Blocks))
	}
	wantSucc := [][]int{{1, 2}, nil, nil} // B0: {fallthrough B1, target B2} sorted
	for i, want := range wantSucc {
		got := cfg.Succ[i]
		if len(got) != len(want) {
			t.Fatalf("succ[%d] = %v, want %v", i, got, want)
		}
		for j := range want {
			if got[j] != want[j] {
				t.Fatalf("succ[%d] = %v, want %v", i, got, want)
			}
		}
	}
	if !cfg.NormalExit[1] || !cfg.NormalExit[2] || cfg.NormalExit[0] {
		t.Fatalf("normal-exit flags wrong: %v", cfg.NormalExit)
	}
	// Determinism: rebuilding yields identical successors.
	again := BuildCFG(c, blocks)
	for i := range cfg.Succ {
		if len(again.Succ[i]) != len(cfg.Succ[i]) {
			t.Fatalf("CFG construction is not deterministic")
		}
	}
}

func TestBuildCFG_DynamicJumpApproximatesAllJumpdests(t *testing.T) {
	// CALL before JUMP makes the target dynamic: successors must be the
	// conservative set of all JUMPDEST blocks.
	// 0: PUSH1 0 2: CALL 3: JUMP 4: JUMPDEST 5: STOP 6: JUMPDEST 7: STOP
	code := []byte{
		byte(opcodes.PUSH1), 0x00, byte(opcodes.CALL), byte(opcodes.JUMP),
		byte(opcodes.JUMPDEST), byte(opcodes.STOP),
		byte(opcodes.JUMPDEST), byte(opcodes.STOP),
	}
	c, blocks := decodeAndSplit(t, "dyn", code)
	cfg := BuildCFG(c, blocks)
	summarize(t, "dyn", code, "dynamic JUMP over-approximates to every JUMPDEST block")
	if len(cfg.Succ[0]) != 2 || cfg.Succ[0][0] != 1 || cfg.Succ[0][1] != 2 {
		t.Fatalf("dynamic jump successors = %v, want [1 2]", cfg.Succ[0])
	}
}

func TestCheckReachableExit(t *testing.T) {
	cases := []struct {
		name    string
		code    []byte
		wantErr bool
		why     string
	}{
		{"stop", []byte{byte(opcodes.STOP)}, false, "STOP is a normal exit"},
		{"selfdestruct", []byte{byte(opcodes.PUSH1), 0, byte(opcodes.SELFDESTRUCT)}, false,
			"SELFDESTRUCT is a normal exit"},
		{"fall_off_end", []byte{byte(opcodes.PUSH1), 0x00}, false,
			"falling off the end is an implicit STOP"},
		{"infinite_loop", []byte{byte(opcodes.JUMPDEST), byte(opcodes.PUSH1), 0x00, byte(opcodes.JUMP)}, true,
			"only reachable path loops forever"},
		{"loop_with_exit", []byte{
			byte(opcodes.JUMPDEST), byte(opcodes.PUSH1), 0x05, byte(opcodes.JUMPI),
			byte(opcodes.STOP), byte(opcodes.JUMPDEST), byte(opcodes.PUSH1), 0x00, byte(opcodes.JUMP),
		}, false, "loop with a JUMPI exit reaches STOP"},
		{"unreachable_exit_ignored", []byte{
			byte(opcodes.JUMPDEST), byte(opcodes.PUSH1), 0x00, byte(opcodes.JUMP),
			byte(opcodes.STOP),
		}, true, "STOP exists but is unreachable from the entry"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, blocks := decodeAndSplit(t, tc.name, tc.code)
			err := CheckReachableExit(c, blocks)
			summarize(t, tc.name, tc.code, tc.why)
			if tc.wantErr {
				var rj *RejectError
				if !errors.As(err, &rj) || rj.Kind != RejectNoReachableExit {
					t.Fatalf("err = %v, want RejectError(%s)", err, RejectNoReachableExit)
				}
				// The new kind must be distinguishable from decode-time kinds.
				for _, k := range []RejectKind{RejectEmpty, RejectInvalidOpcode, RejectTruncatedImmediate, RejectJumpOutOfBounds, RejectJumpNotDest} {
					if rj.Kind == k {
						t.Fatalf("reject kind %s collides with decode-time kind", rj.Kind)
					}
				}
			} else if err != nil {
				t.Fatalf("unexpected rejection: %v", err)
			}
		})
	}
}
