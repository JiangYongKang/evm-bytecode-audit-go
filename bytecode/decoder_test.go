package bytecode

import (
	"errors"
	"testing"

	"github.com/highcumontoa/evm-bytecode-audit-go/opcodes"
)

// summarize prints a short input summary + decision basis into the test
// log, as required by the task (tests must log input digest and rationale).
func summarize(t *testing.T, name string, code []byte, why string) {
	t.Helper()
	t.Logf("input=%s len=%d head=% x -> %s", name, len(code), head(code), why)
}

func head(code []byte) []byte {
	if len(code) <= 8 {
		return code
	}
	return code[:8]
}

func rejectAs(t *testing.T, err error, want RejectKind, wantOff int) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected rejection %s, got nil", want)
	}
	var rj *RejectError
	if !errors.As(err, &rj) {
		t.Fatalf("error is not *RejectError: %T %v", err, err)
	}
	if rj.Kind != want {
		t.Fatalf("reject kind = %q, want %q (detail: %s)", rj.Kind, want, rj.Detail)
	}
	if wantOff >= 0 && rj.Offset != wantOff {
		t.Fatalf("reject offset = %d, want %d", rj.Offset, wantOff)
	}
}

func TestDecode_AcceptsValidBytecode(t *testing.T) {
	code := []byte{
		byte(opcodes.PUSH1), 0x03,
		byte(opcodes.JUMP),
		byte(opcodes.JUMPDEST),
		byte(opcodes.STOP),
	}
	c, err := Decode("valid_jump", code)
	if err != nil {
		t.Fatalf("valid input rejected: %v", err)
	}
	summarize(t, "valid_jump", code, "decoded 4 instructions, static jump to JUMPDEST")
	if len(c.Instructions) != 4 {
		t.Fatalf("instruction count = %d, want 4", len(c.Instructions))
	}
	if c.Instructions[0].Offset != 0 || string(c.Instructions[0].Immediate) != "" && c.Instructions[0].Immediate[0] != 0x03 {
		t.Fatalf("PUSH1 immediate decoded incorrectly: %v", c.Instructions[0])
	}
	// Mutating the caller's buffer must not change the decoded copy.
	code[3] = byte(opcodes.STOP)
	if c.Code[3] != byte(opcodes.JUMPDEST) {
		t.Fatalf("decoder did not defensively copy input")
	}
}

func TestDecode_MalformedInputs(t *testing.T) {
	cases := []struct {
		name   string
		code   []byte
		kind   RejectKind
		offset int
		why    string
	}{
		{"empty", nil, RejectEmpty, -1, "zero length cannot be a contract"},
		{"invalid_opcode", []byte{byte(opcodes.PUSH1), 0, 0x0e, 0x00}, RejectInvalidOpcode, 2,
			"0x0e is not a defined opcode"},
		{"invalid_opcode_0xfe", []byte{0xfe}, RejectInvalidOpcode, 0,
			"explicit INVALID is rejected too"},
		{"truncated_push2", []byte{byte(opcodes.PUSH2), 0x00}, RejectTruncatedImmediate, 0,
			"PUSH2 needs 2 bytes, only 1 present"},
		{"truncated_push32", append([]byte{byte(opcodes.PUSH32)}, make([]byte, 31)...), RejectTruncatedImmediate, 0,
			"PUSH32 needs 32 bytes, only 31 present"},
		{"jump_oob", []byte{byte(opcodes.PUSH1), 0x05, byte(opcodes.JUMP)}, RejectJumpOutOfBounds, 2,
			"target 5 >= length 3"},
		{"jumpi_oob", []byte{byte(opcodes.PUSH1), 0x09, byte(opcodes.JUMPI)}, RejectJumpOutOfBounds, 2,
			"JUMPI target 9 >= length 3"},
		{"jump_not_dest", []byte{byte(opcodes.PUSH1), 0x00, byte(opcodes.JUMP), byte(opcodes.STOP)}, RejectJumpNotDest, 2,
			"target 0 holds PUSH1, not JUMPDEST"},
		{"jumpi_into_push_imm", []byte{byte(opcodes.JUMP), byte(opcodes.PUSH1), byte(opcodes.JUMPDEST), byte(opcodes.PUSH1), 0x01, byte(opcodes.JUMPI)},
			RejectJumpNotDest, 5, "JUMPI target points at a PUSH immediate byte"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			summarize(t, tc.name, tc.code, tc.why)
			_, err := Decode(tc.name, tc.code)
			rejectAs(t, err, tc.kind, tc.offset)
		})
	}
}

func TestDecode_ReasonsAreDistinguishable(t *testing.T) {
	// The same length / similar shape inputs must land in different reason
	// buckets so callers can react differently.
	bad := [][]byte{
		{byte(opcodes.PUSH1), 0, 0x0e},                  // invalid opcode
		{byte(opcodes.PUSH2), 0},                        // truncated
		{byte(opcodes.PUSH1), 0x05, byte(opcodes.JUMP)}, // oob
		{byte(opcodes.PUSH1), 0x00, byte(opcodes.JUMP)}, // not jumpdest
	}
	want := []RejectKind{
		RejectInvalidOpcode,
		RejectTruncatedImmediate,
		RejectJumpOutOfBounds,
		RejectJumpNotDest,
	}
	seen := map[RejectKind]bool{}
	for i, code := range bad {
		_, err := Decode("dist", code)
		var rj *RejectError
		if !errors.As(err, &rj) {
			t.Fatalf("case %d: not a RejectError", i)
		}
		if rj.Kind != want[i] {
			t.Fatalf("case %d: got %s want %s", i, rj.Kind, want[i])
		}
		seen[rj.Kind] = true
	}
	if len(seen) != 4 {
		t.Fatalf("reject reasons collapsed: %v", seen)
	}
	t.Logf("input=4 similar-shaped malformed contracts -> 4 distinct reasons: %v", seen)
}
