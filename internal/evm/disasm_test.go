package evm

import (
	"encoding/hex"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func summary(code []byte) string {
	if len(code) > 16 {
		return hex.EncodeToString(code[:16]) + "..."
	}
	return hex.EncodeToString(code)
}

func TestDecodeValid(t *testing.T) {
	// PUSH1 0x04; JUMP; STOP; JUMPDEST; STOP
	code := mustHex(t, "600456005b00")
	prog, err := Decode(code)
	if err != nil {
		t.Fatalf("input=%s unexpectedly rejected: %v", summary(code), err)
	}
	t.Logf("input=%s blocks=%d instrs=%d", summary(code), len(prog.Blocks), len(prog.Instrs))
	if len(prog.Blocks) != 3 {
		t.Fatalf("want 3 blocks, got %d", len(prog.Blocks))
	}
	if prog.Blocks[2].Start != 4 || prog.Blocks[2].Instrs[0].Op != OpJumpdest {
		t.Fatalf("block#2 should start at JUMPDEST pc=4, got %+v", prog.Blocks[2])
	}
}

func TestDecodeRejectReasons(t *testing.T) {
	cases := []struct {
		name string
		code []byte
		want RejectReason
	}{
		{"empty", nil, ReasonEmpty},
		{"unknown_opcode", mustHex(t, "0c00"), ReasonUnknownOpcode},
		{"truncated_push", mustHex(t, "6101"), ReasonTruncatedPush},
		{"falls_off_end", mustHex(t, "600050"), ReasonTooShort},
		{"jump_out_of_range", mustHex(t, "60105600"), ReasonBadJumpDest},
		// 目标 0x03 是 PUSH1 操作码本身，不是 JUMPDEST
		{"jump_to_non_jumpdest", mustHex(t, "600356605b00"), ReasonJumpIntoPush},
		// 目标 0x04 是 PUSH1 的立即数字节（0x5b 恰好像 JUMPDEST）
		{"jump_into_push_data", mustHex(t, "600456605b00"), ReasonJumpIntoPush},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Decode(tc.code)
			if err == nil {
				t.Fatalf("input=%s should be rejected as %s", summary(tc.code), tc.want)
			}
			rej, ok := err.(*RejectError)
			if !ok {
				t.Fatalf("input=%s error type %T, want *RejectError", summary(tc.code), err)
			}
			t.Logf("input=%s rejected: reason=%s offset=%d detail=%q",
				summary(tc.code), rej.Reason, rej.Offset, rej.Detail)
			if rej.Reason != tc.want {
				t.Fatalf("input=%s reason=%s, want %s", summary(tc.code), rej.Reason, tc.want)
			}
		})
	}
}

func TestRejectReasonsAreDistinct(t *testing.T) {
	// 确认各畸形输入的拒绝原因两两可区分。
	inputs := [][]byte{
		nil,
		mustHex(t, "0c00"),
		mustHex(t, "6101"),
		mustHex(t, "600050"),
		mustHex(t, "60105600"),
		mustHex(t, "600356605b00"),
	}
	seen := map[RejectReason]int{}
	for _, code := range inputs {
		_, err := Decode(code)
		rej, ok := err.(*RejectError)
		if !ok {
			t.Fatalf("input=%s not a RejectError: %v", summary(code), err)
		}
		seen[rej.Reason]++
	}
	if len(seen) != len(inputs) {
		t.Fatalf("reject reasons not distinct: %v", seen)
	}
	t.Logf("distinct reject reasons confirmed: %v", seen)
}
