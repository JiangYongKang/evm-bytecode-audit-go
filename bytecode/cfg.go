package bytecode

import (
	"sort"

	"github.com/highcumontoa/evm-bytecode-audit-go/opcodes"
)

// CFG is the static control-flow graph of a decoded contract, built on top
// of its basic blocks. Edges are derived only from statically resolvable
// control flow:
//   - JUMP/JUMPI with an immediately preceding PUSHk target -> edge to the
//     block starting at that JUMPDEST (already validated by Decode);
//   - JUMPI also keeps the fall-through edge to the next block;
//   - any other non-terminating block falls through to the next block.
//
// Dynamic jump targets (not statically known) produce no edge; blocks whose
// last instruction is such a jump are flagged via HasDynamicJump so
// reachability clients can treat them as "unknown successors" instead of
// "no successors".
type CFG struct {
	Blocks []Block
	// Succ[i] holds the successor block indices of Blocks[i], sorted by
	// successor block Start offset, deduplicated. Deterministic.
	Succ [][]int
	// HasDynamicJump[i] is true when Blocks[i] ends in JUMP/JUMPI whose
	// target cannot be statically resolved.
	HasDynamicJump []bool
	// Entry is the entry block index (always 0 when blocks exist).
	Entry int
}

// BuildCFG constructs the control-flow graph for a decoded contract and its
// basic blocks. The result is deterministic for a given input: successor
// lists are deduplicated and sorted by the successor block's Start offset.
func BuildCFG(c *DecodedContract, blocks []Block) *CFG {
	cfg := &CFG{
		Blocks:         blocks,
		Succ:           make([][]int, len(blocks)),
		HasDynamicJump: make([]bool, len(blocks)),
	}
	if len(blocks) == 0 {
		return cfg
	}

	byStart := make(map[int]int, len(blocks))
	for i, b := range blocks {
		byStart[b.Start] = i
	}

	for i, b := range blocks {
		last := b.Insts[len(b.Insts)-1]
		succ := map[int]bool{}
		switch last.Op {
		case opcodes.STOP, opcodes.RETURN, opcodes.REVERT,
			opcodes.SELFDESTRUCT, opcodes.INVALID:
			// Halting block: no successors.
		case opcodes.JUMP:
			if t, ok := staticTarget(b); ok {
				succ[byStart[t]] = true
			} else {
				cfg.HasDynamicJump[i] = true
			}
		case opcodes.JUMPI:
			if i+1 < len(blocks) {
				succ[i+1] = true // fall-through
			}
			if t, ok := staticTarget(b); ok {
				succ[byStart[t]] = true
			} else {
				cfg.HasDynamicJump[i] = true
			}
		default:
			if i+1 < len(blocks) {
				succ[i+1] = true // plain fall-through
			}
		}
		cfg.Succ[i] = sortedIndices(succ, blocks)
	}
	return cfg
}

// staticTarget returns the jump target of a block whose last instruction is
// JUMP/JUMPI, when the instruction immediately before it is a PUSHk. The
// target is guaranteed to be the Start of some block because Decode already
// validated that it lands on a JUMPDEST (and every JUMPDEST opens a block).
func staticTarget(b Block) (int, bool) {
	n := len(b.Insts)
	if n < 2 {
		return 0, false
	}
	prev := b.Insts[n-2]
	if !opcodes.IsPush(prev.Op) || len(prev.Immediate) == 0 {
		return 0, false
	}
	return int(decodePaddedUint(prev.Immediate)), true
}

// sortedIndices flattens a set of block indices into a slice sorted by the
// blocks' Start offsets (equivalently: by block index, since blocks are
// emitted in offset order). Sorting keeps traversal order deterministic.
func sortedIndices(set map[int]bool, blocks []Block) []int {
	out := make([]int, 0, len(set))
	for idx := range set {
		out = append(out, idx)
	}
	sort.Slice(out, func(a, b int) bool { return blocks[out[a]].Start < blocks[out[b]].Start })
	return out
}
