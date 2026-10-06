package rules

import (
	"fmt"

	"github.com/highcumontoa/evm-bytecode-audit-go/bytecode"
	"github.com/highcumontoa/evm-bytecode-audit-go/opcodes"
)

// UnprotectedPrivilegedRuleVersion is bumped whenever this rule's semantics
// change.
//
// 2.0.0: upgraded from a local instruction-window heuristic to path-level
// guard domination over the static control-flow graph.
const UnprotectedPrivilegedRuleVersion = "2.0.0"

// UnprotectedPrivilegedRule flags SELFDESTRUCT instructions that are not
// guarded by a caller-identity check on every executable path.
//
// Semantics (path-sensitive): a basic block "establishes a guard" when it
// contains CALLER followed by EQ (the ownership pattern
//
//	PUSH <owner>  CALLER  EQ  ISZERO  PUSH <deny>  JUMPI
//
// ). A SELFDESTRUCT is protected iff EVERY statically reachable path from
// the entry block to it passes through a guard block — where, for the
// SELFDESTRUCT's own block, the CALLER/EQ pair must appear before the
// SELFDESTRUCT itself. As soon as one reachable path from the entry arrives
// without having established the guard, the instruction is reported once,
// with the bypassing path's key offsets in execution order as evidence.
//
// The guard may live in any earlier block (e.g. behind a conditional jump);
// what matters is that no path can bypass it. The search is a BFS over
// (block, guard-established) states, so loops and back edges converge
// through the visited set (at most 2 states per block) and each
// SELFDESTRUCT yields at most one finding. A SELFDESTRUCT unreachable from
// the entry is vacuously protected and not reported.
type UnprotectedPrivilegedRule struct{}

func (r UnprotectedPrivilegedRule) ID() RuleID      { return RuleUnprotectedPrivileged }
func (r UnprotectedPrivilegedRule) Version() string { return UnprotectedPrivilegedRuleVersion }

// guardState is a BFS state: a block plus whether the caller-identity
// guard has been established on the way to it.
type guardState struct {
	block   int
	guarded bool
}

func (r UnprotectedPrivilegedRule) Check(contract *bytecode.DecodedContract, blocks []bytecode.Block) []Finding {
	cfg := bytecode.BuildCFG(contract, blocks)
	if len(blocks) == 0 {
		return nil
	}
	px := newPathIndex(contract, blocks)
	insts := px.insts
	blkOf := px.blkOf

	// guardBlock[b] is true when block b contains CALLER followed by EQ.
	guardBlock := make([]bool, len(blocks))
	for i, b := range blocks {
		guardBlock[i] = hasCallerEq(b.Insts, len(b.Insts))
	}

	// BFS from the entry over (block, guardedBefore) states, where
	// guardedBefore means the guard was established in a block BEFORE this
	// one. Keeping the current block's own guard out of its entry state
	// lets the per-SELFDESTRUCT prefix check decide whether an in-block
	// guard actually precedes it. Deterministic: FIFO queue, successors in
	// CFG (offset-sorted) order.
	parent := map[guardState]guardState{}
	visited := map[guardState]bool{}
	var queue []guardState
	push := func(s, from guardState) {
		if visited[s] {
			return
		}
		visited[s] = true
		parent[s] = from
		queue = append(queue, s)
	}
	entry := guardState{block: cfg.Entry, guarded: false}
	push(entry, guardState{block: -1})

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, s := range cfg.Succ[cur.block] {
			push(guardState{block: s, guarded: cur.guarded || guardBlock[cur.block]}, cur)
		}
	}

	var findings []Finding
	for sdIdx, ins := range insts {
		if !opcodes.IsPrivileged(ins.Op) {
			continue
		}
		b := blkOf[sdIdx]
		// Positions of the SELFDESTRUCT inside its own block, to require
		// any in-block guard to precede it.
		posInBlock := sdIdx - px.blkStart[b]
		prefixGuard := hasCallerEq(blocks[b].Insts, posInBlock)

		// Find an unguarded arrival state, if any.
		var bypass *guardState
		for _, g := range []bool{false, true} {
			st := guardState{block: b, guarded: g}
			if !visited[st] {
				continue
			}
			if g || prefixGuard {
				continue // this arrival is protected
			}
			s := st
			bypass = &s
			break
		}
		if bypass == nil {
			continue // every reachable path is guarded (or unreachable)
		}

		path, pathBlocks := r.witness(cfg, parent, *bypass, ins.Offset)
		findings = append(findings, Finding{
			RuleID:   r.ID(),
			Severity: SeverityHigh,
			Message: fmt.Sprintf(
				"%s at offset %d is reachable from entry along a path with no CALLER/EQ ownership check",
				opcodes.Lookup(ins.Op).Name, ins.Offset),
			Evidence: []Evidence{{
				Description: "an execution path from the contract entry reaches the privileged instruction without passing a caller-identity equality check; offsets list the path's key positions in execution order",
				Offsets:     path,
				Details: map[string]any{
					"privileged_offset": ins.Offset,
					"privileged_opcode": "SELFDESTRUCT",
					"path_blocks":       pathBlocks,
					"missing_guard":     missingGuard(cfg, pathBlocks),
					"rule_version":      UnprotectedPrivilegedRuleVersion,
				},
			}},
		})
	}
	return findings
}

// witness reconstructs the execution-ordered key offsets of the BFS path
// that reached state `leaf`: the entry offset of every block on the path
// followed by the privileged instruction's own offset. It also returns the
// block indices along the path.
func (r UnprotectedPrivilegedRule) witness(cfg *bytecode.CFG, parent map[guardState]guardState, leaf guardState, sdOff int) ([]int, []int) {
	var chain []guardState
	for s := leaf; s.block >= 0; s = parent[s] {
		chain = append(chain, s)
	}
	path := make([]int, 0, len(chain)+1)
	pathBlocks := make([]int, 0, len(chain))
	for i := len(chain) - 1; i >= 0; i-- {
		path = append(path, cfg.Blocks[chain[i].block].Start)
		pathBlocks = append(pathBlocks, chain[i].block)
	}
	return append(path, sdOff), pathBlocks
}

// hasCallerEq reports whether insts[:limit] contains CALLER followed by EQ.
func hasCallerEq(insts []opcodes.Instruction, limit int) bool {
	seenCaller := false
	for i := 0; i < limit && i < len(insts); i++ {
		switch insts[i].Op {
		case opcodes.CALLER:
			seenCaller = true
		case opcodes.EQ:
			if seenCaller {
				return true
			}
		}
	}
	return false
}

// missingGuard describes which part of the CALLER/EQ pattern never appears
// along the bypassing path's blocks.
func missingGuard(cfg *bytecode.CFG, pathBlocks []int) string {
	seenCaller, seenPair := false, false
	for _, b := range pathBlocks {
		if hasCallerEq(cfg.Blocks[b].Insts, len(cfg.Blocks[b].Insts)) {
			seenPair = true
		}
		for _, ins := range cfg.Blocks[b].Insts {
			if ins.Op == opcodes.CALLER {
				seenCaller = true
			}
		}
	}
	switch {
	case !seenCaller:
		return "CALLER and EQ"
	case !seenPair:
		return "EQ"
	default:
		return "none (guard exists but is bypassed on this path)"
	}
}
