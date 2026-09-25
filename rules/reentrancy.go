package rules

import (
	"fmt"

	"github.com/highcumontoa/evm-bytecode-audit-go/bytecode"
	"github.com/highcumontoa/evm-bytecode-audit-go/opcodes"
)

// ReentrancyRuleVersion is bumped whenever this rule's semantics change.
const ReentrancyRuleVersion = "1.0.0"

// ReentrancyRule flags state writes (SSTORE) performed after an external
// call (CALL/CALLCODE/DELEGATECALL) within the same basic block with no
// intervening halting instruction. STATICCALL is excluded because it cannot
// transfer control to state-mutating external code.
//
// This is a deliberately conservative local shape: it catches the textbook
// "external call before state update" ordering without claiming global
// path sensitivity.
type ReentrancyRule struct{}

func (r ReentrancyRule) ID() RuleID      { return RuleReentrancy }
func (r ReentrancyRule) Version() string { return ReentrancyRuleVersion }

func (r ReentrancyRule) Check(contract *bytecode.DecodedContract, blocks []bytecode.Block) []Finding {
	var findings []Finding
	for _, blk := range blocks {
		var callOff int = -1
		var callName string
		for _, ins := range blk.Insts {
			switch {
			case opcodes.IsExternalCall(ins.Op):
				callOff = ins.Offset
				callName = opcodes.Lookup(ins.Op).Name
			case opcodes.IsStateWrite(ins.Op) && callOff >= 0:
				findings = append(findings, Finding{
					RuleID:   r.ID(),
					Severity: SeverityHigh,
					Message:  fmt.Sprintf("state write at offset %d follows external %s at offset %d within block %d (reentrancy window)", ins.Offset, callName, callOff, blk.Index),
					Evidence: []Evidence{{
						Description: "external call precedes storage write before any halting instruction in the same basic block",
						Offsets:     []int{blk.Start, callOff, ins.Offset},
						Details: map[string]any{
							"block_index":   blk.Index,
							"block_start":   blk.Start,
							"call_offset":   callOff,
							"call_opcode":   callName,
							"sstore_offset": ins.Offset,
							"state_opcode":  "SSTORE",
							"rule_version":  ReentrancyRuleVersion,
						},
					}},
				})
				// Keep scanning; each later SSTORE is a separate hit.
			}
		}
	}
	return findings
}
