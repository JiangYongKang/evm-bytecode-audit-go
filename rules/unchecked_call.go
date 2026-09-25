package rules

import (
	"fmt"

	"github.com/highcumontoa/evm-bytecode-audit-go/bytecode"
	"github.com/highcumontoa/evm-bytecode-audit-go/opcodes"
)

// UncheckedCallRuleVersion is bumped whenever this rule's semantics change.
const UncheckedCallRuleVersion = "1.0.0"

// UncheckedCallRule flags CALL/CALLCODE/DELEGATECALL instructions whose
// success bit (a 0/1 value pushed on the stack) is removed by an immediate
// POP rather than tested (e.g. PUSH ... <success> ISZERO JUMPI or
// <success> PUSH ... EQ JUMPI).
//
// The rule is local and intentionally precise: only a POP at the very next
// instruction is flagged, because in that shape the EVM gives the caller no
// chance to branch on failure. Any other successor (ISZERO, EQ, JUMPI,
// DUP...) is treated as "possibly checked" and is not reported.
type UncheckedCallRule struct{}

func (r UncheckedCallRule) ID() RuleID      { return RuleUncheckedCall }
func (r UncheckedCallRule) Version() string { return UncheckedCallRuleVersion }

func (r UncheckedCallRule) Check(contract *bytecode.DecodedContract, blocks []bytecode.Block) []Finding {
	var findings []Finding
	for _, blk := range blocks {
		for i := 0; i+1 < len(blk.Insts); i++ {
			call := blk.Insts[i]
			if !opcodes.IsExternalCall(call.Op) {
				continue
			}
			next := blk.Insts[i+1]
			if next.Op != opcodes.POP {
				continue
			}
			name := opcodes.Lookup(call.Op).Name
			findings = append(findings, Finding{
				RuleID:   r.ID(),
				Severity: SeverityMedium,
				Message:  fmt.Sprintf("return value of %s at offset %d is discarded by POP at offset %d", name, call.Offset, next.Offset),
				Evidence: []Evidence{{
					Description: "external call immediately followed by POP; the success bit is never tested",
					Offsets:     []int{call.Offset, next.Offset},
					Details: map[string]any{
						"block_index":  blk.Index,
						"call_offset":  call.Offset,
						"call_opcode":  name,
						"pop_offset":   next.Offset,
						"rule_version": UncheckedCallRuleVersion,
					},
				}},
			})
		}
	}
	return findings
}
