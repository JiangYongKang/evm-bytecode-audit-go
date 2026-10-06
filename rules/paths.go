package rules

import (
	"github.com/highcumontoa/evm-bytecode-audit-go/bytecode"
	"github.com/highcumontoa/evm-bytecode-audit-go/opcodes"
)

// pathIndex precomputes the instruction/block cross-references every
// path-level rule needs, exactly once per contract, so per-query BFS work
// stays proportional to the number of explored states.
type pathIndex struct {
	insts    []opcodes.Instruction // flat instruction slice (shared, not copied)
	blkOf    []int                 // instruction index -> block index
	blkStart []int                 // block index -> first instruction index
}

// newPathIndex indexes the contract's instructions against its blocks.
// Blocks are emitted in instruction order, so the mapping is a single
// linear pass.
func newPathIndex(contract *bytecode.DecodedContract, blocks []bytecode.Block) *pathIndex {
	insts := contract.Instructions
	p := &pathIndex{
		insts:    insts,
		blkOf:    make([]int, len(insts)),
		blkStart: make([]int, len(blocks)),
	}
	idx := 0
	for bi, b := range blocks {
		p.blkStart[bi] = idx
		for range b.Insts {
			p.blkOf[idx] = bi
			idx++
		}
	}
	return p
}
