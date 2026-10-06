package rules

import (
	"fmt"

	"github.com/highcumontoa/evm-bytecode-audit-go/bytecode"
	"github.com/highcumontoa/evm-bytecode-audit-go/opcodes"
)

// ReentrancyRuleVersion is bumped whenever this rule's semantics change.
//
//	1.0.0: same-basic-block CALL..SSTORE adjacency.
//	2.0.0: path-sensitive reachability over the control-flow graph.
const ReentrancyRuleVersion = "2.0.0"

// ReentrancyRule flags an external call (CALL/CALLCODE/DELEGATECALL) when
// ANY execution path leading out of it can reach a state write (SSTORE),
// no matter how many basic blocks, branches, merges or jump detours lie in
// between. STATICCALL is excluded because it cannot transfer control to
// state-mutating external code.
//
// Semantics (may-analysis): for each external call site, explore the CFG
// from the instruction right after the call. If some reachable instruction
// is an SSTORE, the call is reported once, with one witness path listed in
// execution order (call offset, then the start offset of every block the
// path passes through, then the SSTORE offset). If no reachable path can
// write state (e.g. every path halts first), nothing is reported.
//
// The witness path is the shortest one found by a breadth-first search over
// successors sorted by block index, so it is deterministic: the same input
// always yields the same path, offsets and finding order.
type ReentrancyRule struct{}

func (r ReentrancyRule) ID() RuleID      { return RuleReentrancy }
func (r ReentrancyRule) Version() string { return ReentrancyRuleVersion }

func (r ReentrancyRule) Check(contract *bytecode.DecodedContract, blocks []bytecode.Block) []Finding {
	cfg := bytecode.BuildCFG(contract, blocks)
	var findings []Finding
	for bi, blk := range blocks {
		for ii, ins := range blk.Insts {
			if !opcodes.IsExternalCall(ins.Op) {
				continue
			}
			path, sstoreOff, ok := findWritePath(cfg, bi, ii)
			if !ok {
				continue
			}
			callName := opcodes.Lookup(ins.Op).Name
			pathOffsets := make([]int, 0, len(path)+2)
			pathOffsets = append(pathOffsets, ins.Offset)
			for _, b := range path[1:] {
				pathOffsets = append(pathOffsets, blocks[b].Start)
			}
			pathOffsets = append(pathOffsets, sstoreOff)
			findings = append(findings, Finding{
				RuleID:   r.ID(),
				Severity: SeverityHigh,
				Message: fmt.Sprintf("state write at offset %d is reachable from external %s at offset %d via %d block(s) (reentrancy window)",
					sstoreOff, callName, ins.Offset, len(path)),
				Evidence: []Evidence{{
					Description: "a control-flow path from the external call reaches a storage write; offsets are in execution order",
					Offsets:     pathOffsets,
					Details: map[string]any{
						"call_offset":   ins.Offset,
						"call_opcode":   callName,
						"sstore_offset": sstoreOff,
						"state_opcode":  "SSTORE",
						"path_blocks":   append([]int(nil), path...),
						"path_offsets":  append([]int(nil), pathOffsets...),
						"rule_version":  ReentrancyRuleVersion,
					},
				}},
			})
		}
	}
	return findings
}

// findWritePath searches for a state write reachable from the program point
// immediately after instruction callIdx in block startBlk. It returns the
// witness path as a list of block indices in execution order (starting with
// startBlk) plus the offset of the reachable SSTORE.
func findWritePath(cfg *bytecode.CFG, startBlk, callIdx int) (path []int, sstoreOff int, ok bool) {
	blocks := cfg.Blocks

	// 1. Straight-line suffix of the call's own block.
	for j := callIdx + 1; j < len(blocks[startBlk].Insts); j++ {
		if blocks[startBlk].Insts[j].Op == opcodes.SSTORE {
			return []int{startBlk}, blocks[startBlk].Insts[j].Offset, true
		}
	}

	// 2. BFS over successor blocks. Successor lists are sorted, so the
	// first path found is deterministic.
	n := len(blocks)
	visited := make([]bool, n)
	parent := make([]int, n)
	for i := range parent {
		parent[i] = -1
	}
	queue := make([]int, 0, n)
	for _, s := range cfg.Succ[startBlk] {
		if !visited[s] {
			visited[s] = true
			parent[s] = startBlk
			queue = append(queue, s)
		}
	}
	for len(queue) > 0 {
		b := queue[0]
		queue = queue[1:]
		for _, ins := range blocks[b].Insts {
			if ins.Op == opcodes.SSTORE {
				// Reconstruct the path b -> ... -> startBlk, then reverse.
				rev := []int{b}
				for cur := b; cur != startBlk; cur = parent[cur] {
					rev = append(rev, parent[cur])
				}
				path = make([]int, len(rev))
				for i, v := range rev {
					path[len(rev)-1-i] = v
				}
				return path, ins.Offset, true
			}
		}
		for _, s := range cfg.Succ[b] {
			if !visited[s] {
				visited[s] = true
				parent[s] = b
				queue = append(queue, s)
			}
		}
	}
	return nil, 0, false
}
