package rules

import (
	"fmt"

	"github.com/highcumontoa/evm-bytecode-audit-go/bytecode"
	"github.com/highcumontoa/evm-bytecode-audit-go/opcodes"
)

// UnprotectedPrivilegedRuleVersion is bumped whenever this rule's semantics
// change.
//
//	1.0.0: CALLER+EQ must appear in the local window before SELFDESTRUCT.
//	2.0.0: path-sensitive must-analysis over the control-flow graph.
const UnprotectedPrivilegedRuleVersion = "2.0.0"

// UnprotectedPrivilegedRule flags SELFDESTRUCT instructions that are not
// guarded by a caller-identity check on every executable path.
//
// Semantics (must-analysis): a guard is a point where both CALLER and EQ
// have been executed (the ownership pattern
// PUSH <owner>; CALLER; EQ; ISZERO; PUSH <deny>; JUMPI). A SELFDESTRUCT is
// protected only when EVERY reachable path from the entry block to it has
// completed a guard beforehand — including guards living in other basic
// blocks or behind conditional jumps. If any reachable path can arrive
// without passing a guard, the instruction is reported once, with one
// witness bypass path in execution order (entry offset, then the start
// offset of every block on the path, then the SELFDESTRUCT offset).
//
// Loops and back edges are handled by a monotone greatest-fixpoint
// computation over the CFG, which always converges and never duplicates or
// skips findings. Unreachable SELFDESTRUCT instructions (no path from the
// entry) cannot execute and are not reported.
type UnprotectedPrivilegedRule struct{}

func (r UnprotectedPrivilegedRule) ID() RuleID      { return RuleUnprotectedPrivileged }
func (r UnprotectedPrivilegedRule) Version() string { return UnprotectedPrivilegedRuleVersion }

func (r UnprotectedPrivilegedRule) Check(contract *bytecode.DecodedContract, blocks []bytecode.Block) []Finding {
	cfg := bytecode.BuildCFG(contract, blocks)
	n := len(blocks)
	if n == 0 {
		return nil
	}

	reachable := make([]bool, n)
	for _, b := range cfg.Reachable() {
		reachable[b] = true
	}

	// guardBlock[b]: a guard completes somewhere inside block b, so every
	// path leaving b has seen CALLER+EQ.
	guardBlock := make([]bool, n)
	for i, blk := range blocks {
		guardBlock[i] = blockHasGuard(blk, len(blk.Insts))
	}

	// Must-analysis, greatest fixpoint:
	//   in[entry] = false (nothing checked before the entry)
	//   in[b]     = AND over reachable predecessors p of out[p]
	//   out[b]    = in[b] || guardBlock[b]
	// Iterating from all-true only flips bits true->false, so it converges
	// within n+1 passes even with loops and back edges.
	in := make([]bool, n)
	out := make([]bool, n)
	for i := range in {
		in[i] = true
		out[i] = true
	}
	in[cfg.Entry] = false
	out[cfg.Entry] = guardBlock[cfg.Entry]
	for changed := true; changed; {
		changed = false
		for b := 0; b < n; b++ {
			if !reachable[b] || b == cfg.Entry {
				continue
			}
			v := true
			hasPred := false
			for p := 0; p < n; p++ {
				if !reachable[p] {
					continue
				}
				for _, s := range cfg.Succ[p] {
					if s == b {
						hasPred = true
						if !out[p] {
							v = false
						}
					}
				}
			}
			if !hasPred {
				continue // unreachable from entry within the reachable set
			}
			if in[b] != v {
				in[b] = v
				changed = true
			}
			if nv := in[b] || guardBlock[b]; out[b] != nv {
				out[b] = nv
				changed = true
			}
		}
	}

	var findings []Finding
	for bi, blk := range blocks {
		if !reachable[bi] {
			continue
		}
		for ii, ins := range blk.Insts {
			if !opcodes.IsPrivileged(ins.Op) {
				continue
			}
			// Guarded if every incoming path completed a guard, or the
			// guard completes inside this block before the SELFDESTRUCT.
			if in[bi] || blockHasGuard(blk, ii) {
				continue
			}
			witness := findUnguardedPath(cfg, guardBlock, bi)
			offsets := []int{blocks[cfg.Entry].Start}
			for _, b := range witness[1:] {
				offsets = append(offsets, blocks[b].Start)
			}
			offsets = append(offsets, ins.Offset)
			findings = append(findings, Finding{
				RuleID:   r.ID(),
				Severity: SeverityHigh,
				Message: fmt.Sprintf("%s at offset %d is reachable from the entry via %d block(s) without a CALLER/EQ ownership check",
					opcodes.Lookup(ins.Op).Name, ins.Offset, len(witness)),
				Evidence: []Evidence{{
					Description: "an execution path from the entry reaches the privileged instruction without completing a caller-identity guard; offsets are in execution order",
					Offsets:     offsets,
					Details: map[string]any{
						"privileged_offset": ins.Offset,
						"privileged_opcode": "SELFDESTRUCT",
						"path_blocks":       append([]int(nil), witness...),
						"path_offsets":      append([]int(nil), offsets...),
						"missing_guard":     missingGuard(blocks, witness),
						"rule_version":      UnprotectedPrivilegedRuleVersion,
					},
				}},
			})
		}
	}
	return findings
}

// blockHasGuard reports whether both CALLER and EQ appear within the first
// `upto` instructions of blk (upto == len(blk.Insts) checks the whole
// block).
func blockHasGuard(blk bytecode.Block, upto int) bool {
	caller, eq := false, false
	for j := 0; j < upto && j < len(blk.Insts); j++ {
		switch blk.Insts[j].Op {
		case opcodes.CALLER:
			caller = true
		case opcodes.EQ:
			eq = true
		}
	}
	return caller && eq
}

// findUnguardedPath returns the shortest path (block indices, starting at
// the entry) that reaches target without passing through a block that
// completes a guard. BFS over sorted successor lists keeps it
// deterministic. The fixpoint guarantees such a path exists whenever it is
// called for an unguarded target.
func findUnguardedPath(cfg *bytecode.CFG, guardBlock []bool, target int) []int {
	n := len(cfg.Blocks)
	visited := make([]bool, n)
	parent := make([]int, n)
	for i := range parent {
		parent[i] = -1
	}
	entry := cfg.Entry
	visited[entry] = true
	queue := []int{entry}
	for len(queue) > 0 {
		b := queue[0]
		queue = queue[1:]
		if b == target {
			rev := []int{b}
			for cur := b; parent[cur] != -1; cur = parent[cur] {
				rev = append(rev, parent[cur])
			}
			path := make([]int, len(rev))
			for i, v := range rev {
				path[len(rev)-1-i] = v
			}
			return path
		}
		if guardBlock[b] {
			continue // entering through here would complete the guard
		}
		for _, s := range cfg.Succ[b] {
			if !visited[s] {
				visited[s] = true
				parent[s] = b
				queue = append(queue, s)
			}
		}
	}
	return []int{entry, target} // unreachable in practice; keeps output total
}

// missingGuard describes which half of the CALLER/EQ pair is absent along
// the witness path, mirroring the v1 detail field.
func missingGuard(blocks []bytecode.Block, path []int) string {
	caller, eq := false, false
	for _, b := range path {
		for _, ins := range blocks[b].Insts {
			switch ins.Op {
			case opcodes.CALLER:
				caller = true
			case opcodes.EQ:
				eq = true
			}
		}
	}
	switch {
	case caller && !eq:
		return "EQ"
	case eq && !caller:
		return "CALLER"
	case caller && eq:
		return "guard not completed before the privileged instruction"
	default:
		return "CALLER and EQ"
	}
}
