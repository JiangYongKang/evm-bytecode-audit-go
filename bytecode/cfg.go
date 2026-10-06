package bytecode

import (
	"encoding/binary"
	"fmt"

	"github.com/highcumontoa/evm-bytecode-audit-go/opcodes"
)

// RejectNoReachableExit means no reachable execution path ends in a normal
// halt (STOP / RETURN / SELFDESTRUCT, or falling off the end of the code).
// It is distinct from malformed-bytecode rejections: the input decodes and
// its static jumps are valid, yet every reachable path either loops forever
// or can only abort (REVERT).
const RejectNoReachableExit RejectKind = "no_reachable_exit"

// CFG is the control-flow graph of a decoded contract, built over its basic
// blocks. Successor lists are sorted ascending by block index, so every
// traversal of the same CFG visits nodes in the same order.
//
// Jump target resolution:
//   - PUSHk <target> immediately before JUMP/JUMPI resolves statically; the
//     decoder already guarantees such targets land on a JUMPDEST.
//   - Dynamically computed targets cannot be resolved statically and are
//     approximated as "any JUMPDEST block" (a conservative may-analysis
//     over-approximation), documented so conclusions stay explainable.
type CFG struct {
	Blocks []Block
	Succ   [][]int // Succ[i] = sorted, deduplicated successor block indices
	Entry  int     // always 0 when Blocks is non-empty
	// NormalExit[i] reports whether block i can end execution normally:
	// it terminates in STOP, RETURN or SELFDESTRUCT, or it is the last
	// block and falls off the end of the bytecode (an implicit STOP).
	NormalExit []bool
}

// BuildCFG constructs the control-flow graph for already-split blocks.
// The result is deterministic for a given input.
func BuildCFG(c *DecodedContract, blocks []Block) *CFG {
	n := len(blocks)
	cfg := &CFG{Blocks: blocks, Succ: make([][]int, n), NormalExit: make([]bool, n)}
	if n == 0 {
		cfg.Entry = -1
		return cfg
	}

	// JUMPDEST offset -> owning block index. SplitBlocks starts a block at
	// every JUMPDEST, so the block's first instruction is the JUMPDEST.
	dest := make(map[int]int)
	var jumpdestBlocks []int
	for i, b := range blocks {
		if len(b.Insts) > 0 && b.Insts[0].Op == opcodes.JUMPDEST {
			dest[b.Start] = i
			jumpdestBlocks = append(jumpdestBlocks, i)
		}
	}

	for i, b := range blocks {
		last := b.Insts[len(b.Insts)-1]
		switch last.Op {
		case opcodes.STOP, opcodes.RETURN, opcodes.SELFDESTRUCT:
			cfg.NormalExit[i] = true // halting: no successors
		case opcodes.REVERT:
			// Abnormal halt: no successors, not a normal exit.
		case opcodes.JUMP:
			cfg.Succ[i] = jumpTargets(b, dest, jumpdestBlocks)
		case opcodes.JUMPI:
			s := jumpTargets(b, dest, jumpdestBlocks)
			if i+1 < n {
				s = append(s, i+1) // fall-through when the condition is false
			}
			cfg.Succ[i] = dedupSorted(s)
		default:
			// No terminator: control falls into the next block, or off the
			// end of the code (implicit STOP) for the final block.
			if i+1 < n {
				cfg.Succ[i] = []int{i + 1}
			} else {
				cfg.NormalExit[i] = true
			}
		}
	}
	return cfg
}

// jumpTargets resolves the successor blocks for a block terminated by
// JUMP/JUMPI. A statically pushed target maps to its JUMPDEST block; a
// dynamic target over-approximates to every JUMPDEST block.
func jumpTargets(b Block, dest map[int]int, jumpdestBlocks []int) []int {
	m := len(b.Insts)
	if m >= 2 {
		prev := b.Insts[m-2]
		if opcodes.IsPush(prev.Op) && len(prev.Immediate) > 0 {
			target := int(pushUint(prev.Immediate))
			if idx, ok := dest[target]; ok {
				return []int{idx}
			}
			// Decode() validates static jump targets, so reaching here means
			// the target has no JUMPDEST block; fall back to the dynamic
			// approximation rather than dropping the edge.
		}
	}
	out := make([]int, len(jumpdestBlocks))
	copy(out, jumpdestBlocks)
	return out
}

// dedupSorted sorts ascending and removes duplicates, keeping traversal
// order deterministic.
func dedupSorted(s []int) []int {
	if len(s) == 0 {
		return nil
	}
	sorted := make([]int, len(s))
	copy(sorted, s)
	for i := 1; i < len(sorted); i++ { // insertion sort: tiny slices
		for j := i; j > 0 && sorted[j] < sorted[j-1]; j-- {
			sorted[j], sorted[j-1] = sorted[j-1], sorted[j]
		}
	}
	out := sorted[:1]
	for _, v := range sorted[1:] {
		if v != out[len(out)-1] {
			out = append(out, v)
		}
	}
	return out
}

// pushUint interprets a PUSH immediate as an unsigned big-endian integer.
func pushUint(b []byte) uint64 {
	if len(b) > 8 {
		return binary.BigEndian.Uint64(b[len(b)-8:])
	}
	var padded [8]byte
	copy(padded[8-len(b):], b)
	return binary.BigEndian.Uint64(padded[:])
}

// Reachable returns the set of block indices reachable from the entry block,
// in ascending order. Traversal is a deterministic BFS.
func (g *CFG) Reachable() []int {
	if g.Entry < 0 {
		return nil
	}
	seen := make([]bool, len(g.Blocks))
	queue := []int{g.Entry}
	seen[g.Entry] = true
	var out []int
	for len(queue) > 0 {
		b := queue[0]
		queue = queue[1:]
		out = append(out, b)
		for _, s := range g.Succ[b] {
			if !seen[s] {
				seen[s] = true
				queue = append(queue, s)
			}
		}
	}
	// out is BFS order; callers get ascending order for stable iteration.
	return dedupSorted(out)
}

// CheckReachableExit verifies that at least one path from the entry block
// reaches a normal exit. It returns a *RejectError with kind
// RejectNoReachableExit when every reachable path loops forever or can only
// abort via REVERT. Unreachable code is ignored: only blocks reachable from
// the entry count.
func CheckReachableExit(c *DecodedContract, blocks []Block) error {
	cfg := BuildCFG(c, blocks)
	if cfg.Entry < 0 {
		return &RejectError{Kind: RejectNoReachableExit, Offset: -1,
			Detail: "no basic blocks: nothing can execute"}
	}
	for _, b := range cfg.Reachable() {
		if cfg.NormalExit[b] {
			return nil
		}
	}
	return &RejectError{
		Kind:   RejectNoReachableExit,
		Offset: -1,
		Detail: fmt.Sprintf("no reachable path from block 0 reaches STOP/RETURN/SELFDESTRUCT or end-of-code (%d reachable block(s) checked)", len(cfg.Reachable())),
	}
}
