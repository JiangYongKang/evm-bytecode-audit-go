// Package samples provides hand-crafted local bytecode contracts used as
// reproducible audit inputs. The bytes are assembled from opcode constants
// (not pulled from any network), and every sample documents the verdict the
// auditor is expected to reach.
package samples

import (
	"github.com/highcumontoa/evm-bytecode-audit-go/audit"
	"github.com/highcumontoa/evm-bytecode-audit-go/opcodes"
)

// Contract is one named sample.
type Contract struct {
	Name   string
	Code   []byte
	Expect string // short, human-readable description of the expected verdict
}

// p1 assembles PUSH1 v.
func p1(v byte) []byte { return []byte{byte(opcodes.PUSH1), v} }

func build(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// All returns every built-in sample in a fixed order: benign contracts,
// risk-bearing contracts, and malformed contracts (which must be rejected).
func All() []Contract {
	return []Contract{
		// ---- benign ----
		{
			Name:   "benign_empty_stop",
			Code:   []byte{byte(opcodes.STOP)},
			Expect: "ok, no findings",
		},
		{
			Name: "benign_valid_jump",
			// PUSH1 3 JUMP JUMPDEST STOP ; static target lands on JUMPDEST
			Code:   build(p1(0x03), []byte{byte(opcodes.JUMP), byte(opcodes.JUMPDEST), byte(opcodes.STOP)}),
			Expect: "ok, no findings, valid static jump",
		},
		{
			Name: "benign_guarded_selfdestruct",
			// PUSH1 0xAA CALLER EQ ISZERO PUSH1 0x0b JUMPI
			// PUSH1 0x00 SELFDESTRUCT JUMPDEST STOP
			Code: build(
				p1(0xAA),
				[]byte{byte(opcodes.CALLER), byte(opcodes.EQ), byte(opcodes.ISZERO)},
				p1(0x0b),
				[]byte{byte(opcodes.JUMPI)},
				p1(0x00),
				[]byte{byte(opcodes.SELFDESTRUCT), byte(opcodes.JUMPDEST), byte(opcodes.STOP)},
			),
			Expect: "ok, no findings (SELFDESTRUCT guarded by CALLER/EQ)",
		},
		{
			Name: "benign_guarded_cross_block",
			// guard in block 0, SELFDESTRUCT in a later block reached only
			// through the guarded path:
			// 0: PUSH1 0xAA CALLER EQ ISZERO PUSH1 0x0b JUMPI
			// 8: PUSH1 0x0d JUMP   11: JUMPDEST STOP   13: JUMPDEST PUSH1 0 SELFDESTRUCT
			Code: build(
				p1(0xAA),
				[]byte{byte(opcodes.CALLER), byte(opcodes.EQ), byte(opcodes.ISZERO)},
				p1(0x0b),
				[]byte{byte(opcodes.JUMPI)},
				p1(0x0d),
				[]byte{byte(opcodes.JUMP), byte(opcodes.JUMPDEST), byte(opcodes.STOP), byte(opcodes.JUMPDEST)},
				p1(0x00),
				[]byte{byte(opcodes.SELFDESTRUCT)},
			),
			Expect: "ok, no findings (guard in an earlier block dominates SELFDESTRUCT)",
		},
		{
			Name: "benign_call_then_halt_dead_sstore",
			// PUSH1 0 CALL STOP | JUMPDEST SSTORE STOP
			// the SSTORE segment is unreachable from the call
			Code: build(
				p1(0x00),
				[]byte{byte(opcodes.CALL), byte(opcodes.STOP), byte(opcodes.JUMPDEST), byte(opcodes.SSTORE), byte(opcodes.STOP)},
			),
			Expect: "ok, no findings (no path from CALL reaches the SSTORE)",
		},

		// ---- risky ----
		{
			Name: "risky_reentrancy",
			// PUSH1 0 PUSH1 0 CALL SSTORE STOP
			Code: build(
				p1(0x00), p1(0x00),
				[]byte{byte(opcodes.CALL), byte(opcodes.SSTORE), byte(opcodes.STOP)},
			),
			Expect: "finding REENTRANCY-STATE-WRITE-AFTER-CALL",
		},
		{
			Name: "risky_reentrancy_cross_block",
			// PUSH1 0 CALL PUSH1 0x06 JUMP | JUMPDEST SSTORE STOP
			// the state write sits in another block reached by a jump
			Code: build(
				p1(0x00),
				[]byte{byte(opcodes.CALL)},
				p1(0x06),
				[]byte{byte(opcodes.JUMP), byte(opcodes.JUMPDEST), byte(opcodes.SSTORE), byte(opcodes.STOP)},
			),
			Expect: "finding REENTRANCY-STATE-WRITE-AFTER-CALL with path [2 6 7]",
		},
		{
			Name: "risky_reentrancy_via_loop",
			// 0: JUMPDEST PUSH1 0 CALL PUSH1 0x0a JUMPI
			// 7: PUSH1 0 JUMP (back edge to 0)
			// 10: JUMPDEST SSTORE STOP
			// the SSTORE is reachable from the CALL only after looping
			Code: build(
				[]byte{byte(opcodes.JUMPDEST)},
				p1(0x00),
				[]byte{byte(opcodes.CALL)},
				p1(0x0a),
				[]byte{byte(opcodes.JUMPI)},
				p1(0x00),
				[]byte{byte(opcodes.JUMP), byte(opcodes.JUMPDEST), byte(opcodes.SSTORE), byte(opcodes.STOP)},
			),
			Expect: "finding REENTRANCY-STATE-WRITE-AFTER-CALL (loop converges, exactly one hit)",
		},
		{
			Name: "risky_guard_bypass_branch",
			// 0: PUSH1 1 PUSH1 0x08 JUMPI          ; cond branch
			// 5: PUSH1 0 SELFDESTRUCT              ; unguarded fallthrough
			// 8: JUMPDEST PUSH1 0xAA CALLER EQ ISZERO PUSH1 0x14 JUMPI
			// 17: PUSH1 0 SELFDESTRUCT             ; guarded
			// 20: JUMPDEST STOP
			Code: build(
				p1(0x01), p1(0x08),
				[]byte{byte(opcodes.JUMPI)},
				p1(0x00),
				[]byte{byte(opcodes.SELFDESTRUCT), byte(opcodes.JUMPDEST)},
				p1(0xAA),
				[]byte{byte(opcodes.CALLER), byte(opcodes.EQ), byte(opcodes.ISZERO)},
				p1(0x14),
				[]byte{byte(opcodes.JUMPI)},
				p1(0x00),
				[]byte{byte(opcodes.SELFDESTRUCT), byte(opcodes.JUMPDEST), byte(opcodes.STOP)},
			),
			Expect: "finding PRIVILEGED-UNPROTECTED-SELFDESTRUCT for offset 7 only (branch bypasses the guard)",
		},
		{
			Name: "risky_unchecked_call",
			// PUSH1 0 CALL POP STOP
			Code: build(
				p1(0x00),
				[]byte{byte(opcodes.CALL), byte(opcodes.POP), byte(opcodes.STOP)},
			),
			Expect: "finding UNCHECKED-CALL-RETURN",
		},
		{
			Name: "risky_unprotected_selfdestruct",
			// PUSH1 0 SELFDESTRUCT
			Code:   build(p1(0x00), []byte{byte(opcodes.SELFDESTRUCT)}),
			Expect: "finding PRIVILEGED-UNPROTECTED-SELFDESTRUCT",
		},
		{
			Name: "risky_combo",
			// PUSH1 0 CALL POP            -> unchecked call
			// PUSH1 0 PUSH1 0 CALL SSTORE -> reentrancy
			// (path semantics: the SSTORE is reachable from BOTH calls,
			//  so two reentrancy findings are expected)
			Code: build(
				p1(0x00), []byte{byte(opcodes.CALL), byte(opcodes.POP)},
				p1(0x00), p1(0x00), []byte{byte(opcodes.CALL), byte(opcodes.SSTORE), byte(opcodes.STOP)},
			),
			Expect: "findings UNCHECKED-CALL-RETURN + 2x reentrancy (SSTORE reachable from both calls)",
		},

		// ---- malformed: must be rejected with distinguishable reasons ----
		{
			Name:   "malformed_empty",
			Code:   nil,
			Expect: "rejected: empty_bytecode",
		},
		{
			Name: "malformed_invalid_opcode",
			// PUSH1 0, then undefined opcode 0x0e
			Code:   build(p1(0x00), []byte{0x0e, 0x00}),
			Expect: "rejected: invalid_opcode at offset 2",
		},
		{
			Name: "malformed_truncated_push",
			// PUSH2 with only one immediate byte
			Code:   []byte{byte(opcodes.PUSH2), 0x00},
			Expect: "rejected: truncated_immediate at offset 0",
		},
		{
			Name: "malformed_jump_out_of_bounds",
			// PUSH1 5 JUMP ; length 3, target 5 is outside
			Code:   build(p1(0x05), []byte{byte(opcodes.JUMP)}),
			Expect: "rejected: jump_target_out_of_bounds",
		},
		{
			Name: "malformed_jump_not_jumpdest",
			// PUSH1 0 JUMP STOP ; target 0 is a PUSH1, not JUMPDEST
			Code:   build(p1(0x00), []byte{byte(opcodes.JUMP), byte(opcodes.STOP)}),
			Expect: "rejected: jump_target_not_jumpdest",
		},
		{
			Name: "malformed_jump_loop_no_halt",
			// JUMPDEST PUSH1 0 JUMP ; an unconditional jump loop that can
			// never reach STOP/RETURN/SELFDESTRUCT or end of code
			Code:   build([]byte{byte(opcodes.JUMPDEST)}, p1(0x00), []byte{byte(opcodes.JUMP)}),
			Expect: "rejected: no_halting_path",
		},
	}
}

// Inputs adapts samples to audit.ContractInput preserving order.
func Inputs(cs []Contract) []audit.ContractInput {
	out := make([]audit.ContractInput, len(cs))
	for i, c := range cs {
		out[i] = audit.ContractInput{Name: c.Name, Code: c.Code}
	}
	return out
}
