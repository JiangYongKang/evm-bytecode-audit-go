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
			Name: "benign_call_then_halt",
			// PUSH1 0 CALL STOP | PUSH1 0 SSTORE
			// The SSTORE lives in a block no reachable path can enter after
			// the call (the call's block halts with STOP): must NOT hit.
			Code: build(
				p1(0x00),
				[]byte{byte(opcodes.CALL), byte(opcodes.STOP)},
				p1(0x00),
				[]byte{byte(opcodes.SSTORE)},
			),
			Expect: "ok, no findings (no reachable path from CALL to SSTORE)",
		},
		{
			Name: "benign_guarded_loop_selfdestruct",
			// Loop with a back edge; the CALLER/EQ guard sits in the loop
			// head and dominates the SELFDESTRUCT on every path.
			// 0: JUMPDEST 1: PUSH1 0xAA 3: CALLER 4: EQ 5: ISZERO
			// 6: PUSH1 0x0d 8: JUMPI 9: PUSH1 0x00 11: SELFDESTRUCT
			// 12: STOP 13: JUMPDEST 14: PUSH1 0x00 16: JUMP (-> 0)
			Code: build(
				[]byte{byte(opcodes.JUMPDEST)},
				p1(0xAA),
				[]byte{byte(opcodes.CALLER), byte(opcodes.EQ), byte(opcodes.ISZERO)},
				p1(0x0d),
				[]byte{byte(opcodes.JUMPI)},
				p1(0x00),
				[]byte{byte(opcodes.SELFDESTRUCT), byte(opcodes.STOP), byte(opcodes.JUMPDEST)},
				p1(0x00),
				[]byte{byte(opcodes.JUMP)},
			),
			Expect: "ok, no findings (guard dominates SELFDESTRUCT; loop converges)",
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
			// PUSH1 0 CALL PUSH1 6 JUMP | JUMPDEST SSTORE STOP
			// The SSTORE is one static jump away from the call: only
			// path-level reachability can see it.
			Code: build(
				p1(0x00),
				[]byte{byte(opcodes.CALL)},
				p1(0x06),
				[]byte{byte(opcodes.JUMP), byte(opcodes.JUMPDEST), byte(opcodes.SSTORE), byte(opcodes.STOP)},
			),
			Expect: "finding REENTRANCY-STATE-WRITE-AFTER-CALL (cross-block path)",
		},
		{
			Name: "risky_privileged_branch_bypass",
			// Entry branches: fall-through reaches SELFDESTRUCT unguarded,
			// the taken branch holds the CALLER/EQ guard. One unguarded
			// reachable path is enough to report.
			// 0: PUSH1 0x07 2: JUMPI 3: PUSH1 0x00 5: SELFDESTRUCT 6: STOP
			// 7: JUMPDEST 8: PUSH1 0xAA 10: CALLER 11: EQ 12: ISZERO
			// 13: PUSH1 0x13 15: JUMPI 16: PUSH1 0x00 18: SELFDESTRUCT
			// 19: JUMPDEST 20: STOP
			Code: build(
				p1(0x07),
				[]byte{byte(opcodes.JUMPI)},
				p1(0x00),
				[]byte{byte(opcodes.SELFDESTRUCT), byte(opcodes.STOP), byte(opcodes.JUMPDEST)},
				p1(0xAA),
				[]byte{byte(opcodes.CALLER), byte(opcodes.EQ), byte(opcodes.ISZERO)},
				p1(0x13),
				[]byte{byte(opcodes.JUMPI)},
				p1(0x00),
				[]byte{byte(opcodes.SELFDESTRUCT), byte(opcodes.JUMPDEST), byte(opcodes.STOP)},
			),
			Expect: "finding PRIVILEGED-UNPROTECTED-SELFDESTRUCT (fall-through bypasses the guard)",
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
			// Path semantics (v2): the first CALL also reaches the SSTORE by
			// falling through, so both call sites are reentrancy hits.
			Code: build(
				p1(0x00), []byte{byte(opcodes.CALL), byte(opcodes.POP)},
				p1(0x00), p1(0x00), []byte{byte(opcodes.CALL), byte(opcodes.SSTORE), byte(opcodes.STOP)},
			),
			Expect: "findings UNCHECKED-CALL-RETURN + reentrancy x2 (both calls reach the SSTORE)",
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
			Name: "malformed_no_reachable_exit",
			// JUMPDEST PUSH1 0 JUMP ; decodes fine, static jump is valid,
			// but the only reachable path loops forever: no normal exit.
			Code: build(
				[]byte{byte(opcodes.JUMPDEST)},
				p1(0x00),
				[]byte{byte(opcodes.JUMP)},
			),
			Expect: "rejected: no_reachable_exit",
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
