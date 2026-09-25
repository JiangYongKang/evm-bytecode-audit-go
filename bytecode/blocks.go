package bytecode

import "github.com/highcumontoa/evm-bytecode-audit-go/opcodes"

// Block is a basic block: a maximal run of instructions with no jumps or
// jump destinations in the middle.
type Block struct {
	Index int
	Start int // byte offset of the first instruction
	End   int // byte offset immediately after the last instruction
	Insts []opcodes.Instruction
}

// terminators end a basic block: STOP/RETURN/REVERT (halt),
// JUMP (leaves the linear stream), JUMPI (may branch away).
func isTerminator(op opcodes.OpCode) bool {
	switch op {
	case opcodes.STOP, opcodes.RETURN, opcodes.REVERT,
		opcodes.JUMP, opcodes.JUMPI, opcodes.SELFDESTRUCT:
		return true
	}
	return false
}

// SplitBlocks partitions a decoded contract into basic blocks in bytecode
// order. A new block starts at offset 0, immediately after a terminator,
// and at every JUMPDEST. The result is deterministic for a given input.
func SplitBlocks(c *DecodedContract) []Block {
	insts := c.Instructions
	if len(insts) == 0 {
		return nil
	}

	boundaries := make(map[int]bool)
	boundaries[insts[0].Offset] = true
	for i, ins := range insts {
		if ins.Op == opcodes.JUMPDEST {
			boundaries[ins.Offset] = true
		}
		if isTerminator(ins.Op) && i+1 < len(insts) {
			boundaries[insts[i+1].Offset] = true
		}
	}

	blocks := make([]Block, 0)
	cur := Block{Start: insts[0].Offset}
	flush := func(endOff int) {
		cur.End = endOff
		cur.Index = len(blocks)
		blocks = append(blocks, cur)
		cur = Block{}
	}

	for i, ins := range insts {
		if i > 0 && boundaries[ins.Offset] && cur.Start != ins.Offset && len(cur.Insts) > 0 {
			flush(ins.Offset)
			cur.Start = ins.Offset
		}
		cur.Insts = append(cur.Insts, ins)
		if isTerminator(ins.Op) {
			nextOff := len(c.Code)
			if i+1 < len(insts) {
				nextOff = insts[i+1].Offset
			}
			flush(nextOff)
			if i+1 < len(insts) {
				cur = Block{Start: insts[i+1].Offset}
			}
		}
	}
	if len(cur.Insts) > 0 {
		flush(len(c.Code))
	}
	return blocks
}
