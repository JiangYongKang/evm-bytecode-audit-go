package rules

import (
	"fmt"
	"sort"

	"github.com/highcumontoa/evm-bytecode-audit-go/bytecode"
	"github.com/highcumontoa/evm-bytecode-audit-go/opcodes"
)

// ReentrancyRuleVersion is bumped whenever this rule's semantics change.
//
// 2.0.0: upgraded from same-basic-block scanning to whole-path reachability
// over the static control-flow graph.
const ReentrancyRuleVersion = "2.0.0"

// ReentrancyRule flags state writes (SSTORE) reachable from an external
// call (CALL/CALLCODE/DELEGATECALL) along any statically resolvable
// execution path. STATICCALL is excluded because it cannot transfer control
// to state-mutating external code.
//
// Semantics (path-sensitive): for each external call, the rule explores the
// control-flow graph starting at the instruction after the call. If any
// reachable path crosses branches, merges or detours through other blocks
// and eventually executes an SSTORE, the (call, sstore) pair is reported
// exactly once, with a witness path listing the key byte offsets in
// execution order. If no reachable path from the call can arrive at any
// SSTORE (e.g. every path halts first), nothing is reported.
//
// The search is a BFS whose states are instruction indices, so loops and
// back edges converge through the visited set: the work is bounded by the
// instruction count and the result order is fully deterministic.
type ReentrancyRule struct{}

func (r ReentrancyRule) ID() RuleID      { return RuleReentrancy }
func (r ReentrancyRule) Version() string { return ReentrancyRuleVersion }

func (r ReentrancyRule) Check(contract *bytecode.DecodedContract, blocks []bytecode.Block) []Finding {
	cfg := bytecode.BuildCFG(contract, blocks)
	px := newPathIndex(contract, blocks)

	var findings []Finding
	for callIdx, ins := range px.insts {
		if !opcodes.IsExternalCall(ins.Op) {
			continue
		}
		findings = append(findings, r.reachableWrites(cfg, px, callIdx)...)
	}
	// Stable emission order: by call offset, then by SSTORE offset.
	sort.SliceStable(findings, func(a, b int) bool {
		da := findings[a].Evidence[0].Details
		db := findings[b].Evidence[0].Details
		ca, cb := da["call_offset"].(int), db["call_offset"].(int)
		if ca != cb {
			return ca < cb
		}
		return da["sstore_offset"].(int) < db["sstore_offset"].(int)
	})
	return findings
}

// reachableWrites BFS-searches every SSTORE reachable from the instruction
// after the call at insts[callIdx]. Each discovered SSTORE yields one
// finding whose evidence carries the witness path in execution order.
func (r ReentrancyRule) reachableWrites(cfg *bytecode.CFG, px *pathIndex, callIdx int) []Finding {
	insts := px.insts
	blkOf := px.blkOf
	call := insts[callIdx]
	callName := opcodes.Lookup(call.Op).Name
	callBlk := blkOf[callIdx]

	// BFS states are instruction indices from which linear scanning
	// resumes: the instruction after the call (same block) and the first
	// instruction of every successor block entered afterwards.
	parent := map[int]int{} // state instIdx -> predecessor state instIdx (-1 for root)
	visited := map[int]bool{}
	var queue []int
	push := func(idx, from int) {
		if idx < 0 || visited[idx] {
			return
		}
		visited[idx] = true
		parent[idx] = from
		queue = append(queue, idx)
	}

	if callIdx+1 < len(insts) && blkOf[callIdx+1] == callBlk {
		push(callIdx+1, -1) // resume inside the call's own block
	}
	for _, s := range cfg.Succ[callBlk] {
		push(px.blkStart[s], -1)
	}

	var findings []Finding
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		b := blkOf[cur]
		// Scan linearly from cur to the end of the block.
		for i := cur; i < len(insts) && blkOf[i] == b; i++ {
			if insts[i].Op != opcodes.SSTORE {
				continue
			}
			path := witnessOffsets(px, cfg, parent, cur, call.Offset, insts[i].Offset)
			findings = append(findings, Finding{
				RuleID:   r.ID(),
				Severity: SeverityHigh,
				Message: fmt.Sprintf(
					"state write at offset %d is reachable from external %s at offset %d along a %d-hop control-flow path (reentrancy window)",
					insts[i].Offset, callName, call.Offset, len(path)-1),
				Evidence: []Evidence{{
					Description: "an execution path from the external call reaches a storage write; offsets list the path's key positions in execution order",
					Offsets:     path,
					Details: map[string]any{
						"call_offset":   call.Offset,
						"call_opcode":   callName,
						"sstore_offset": insts[i].Offset,
						"state_opcode":  "SSTORE",
						"path_blocks":   witnessBlocks(blkOf, parent, cur, callBlk, b),
						"rule_version":  ReentrancyRuleVersion,
					},
				}},
			})
		}
		for _, s := range cfg.Succ[b] {
			push(px.blkStart[s], cur)
		}
	}
	return findings
}

// witnessOffsets reconstructs the execution-ordered key offsets of the BFS
// path that reached state `cur`: the call offset, the entry (JUMPDEST)
// offset of every block entered along the way, and the SSTORE offset. The
// resume point inside the call's own block is not a block entry and is
// omitted (the call offset already covers it).
func witnessOffsets(px *pathIndex, cfg *bytecode.CFG, parent map[int]int, cur, callOff, sstoreOff int) []int {
	insts := px.insts
	blkOf := px.blkOf
	var chain []int
	for s := cur; s >= 0; s = parent[s] {
		chain = append(chain, s)
	}
	out := []int{callOff}
	for i := len(chain) - 1; i >= 0; i-- {
		s := chain[i]
		if insts[s].Offset != cfg.Blocks[blkOf[s]].Start {
			continue // mid-block resume point, not a path waypoint
		}
		out = append(out, insts[s].Offset)
	}
	return append(out, sstoreOff)
}

// witnessBlocks mirrors witnessOffsets but reports block indices.
func witnessBlocks(blkOf []int, parent map[int]int, cur, callBlk, sstoreBlk int) []int {
	var chain []int
	for s := cur; s >= 0; s = parent[s] {
		chain = append(chain, blkOf[s])
	}
	out := []int{callBlk}
	for i := len(chain) - 1; i >= 0; i-- {
		if chain[i] != out[len(out)-1] {
			out = append(out, chain[i])
		}
	}
	if out[len(out)-1] != sstoreBlk {
		out = append(out, sstoreBlk)
	}
	return out
}
