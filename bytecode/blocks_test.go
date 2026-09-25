package bytecode

import (
	"testing"

	"github.com/highcumontoa/evm-bytecode-audit-go/opcodes"
)

func TestSplitBlocks(t *testing.T) {
	// PUSH1 0 CALL SSTORE STOP | PUSH1 0 SELFDESTRUCT
	code := []byte{
		byte(opcodes.PUSH1), 0x00,
		byte(opcodes.CALL), byte(opcodes.SSTORE), byte(opcodes.STOP),
		byte(opcodes.PUSH1), 0x00, byte(opcodes.SELFDESTRUCT),
	}
	c, err := Decode("blocks", code)
	if err != nil {
		t.Fatal(err)
	}
	blocks := SplitBlocks(c)
	summarize(t, "blocks", code, "expect two blocks split at STOP")
	if len(blocks) != 2 {
		t.Fatalf("blocks = %d, want 2", len(blocks))
	}
	if blocks[0].Insts[len(blocks[0].Insts)-1].Op != opcodes.STOP {
		t.Fatalf("block 0 must end in STOP")
	}
	if blocks[1].Insts[0].Op != opcodes.PUSH1 {
		t.Fatalf("block 1 must start with PUSH1")
	}
	// Determinism: splitting twice yields identical structure.
	again := SplitBlocks(c)
	if len(again) != len(blocks) || again[0].Start != blocks[0].Start || again[1].End != blocks[1].End {
		t.Fatalf("block split is not deterministic")
	}
}

func TestSplitBlocks_JumpdestStartsBlock(t *testing.T) {
	// PUSH1 3 JUMPI JUMPDEST STOP  (JUMPI falls through to JUMPDEST)
	code := []byte{byte(opcodes.PUSH1), 0x03, byte(opcodes.JUMPI), byte(opcodes.JUMPDEST), byte(opcodes.STOP)}
	c, err := Decode("jd", code)
	if err != nil {
		t.Fatal(err)
	}
	b := SplitBlocks(c)
	summarize(t, "jd", code, "JUMPDEST begins its own block")
	if len(b) != 2 {
		t.Fatalf("blocks = %d, want 2", len(b))
	}
	if b[1].Insts[0].Op != opcodes.JUMPDEST {
		t.Fatalf("second block must begin at JUMPDEST")
	}
}
