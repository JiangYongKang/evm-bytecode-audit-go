package rules

import (
	"fmt"

	"github.com/highcumontoa/evm-bytecode-audit-go/bytecode"
	"github.com/highcumontoa/evm-bytecode-audit-go/opcodes"
)

// UnprotectedPrivilegedRuleVersion is bumped whenever this rule's semantics
// change.
const UnprotectedPrivilegedRuleVersion = "1.0.0"

// UnprotectedPrivilegedRule flags SELFDESTRUCT instructions for which no
// caller-identity guard is visible in the preceding code window.
//
// A guard is recognized as both CALLER and EQ appearing in the instruction
// window starting immediately after the previous JUMPDEST (or bytecode
// start) and ending at SELFDESTRUCT. This matches the common ownership
// pattern
//
//	PUSH <owner>  CALLER  EQ  ISZERO  PUSH <deny>  JUMPI ... SELFDESTRUCT
//
// where the JUMPI terminates a basic block but the comparison logically
// dominates the SELFDESTRUCT. Other access-control mechanisms (SLOAD-based
// owner records, signatures, etc.) are outside this heuristic and will be
// reported; the rule's local, reviewable nature is intentional.
type UnprotectedPrivilegedRule struct{}

func (r UnprotectedPrivilegedRule) ID() RuleID      { return RuleUnprotectedPrivileged }
func (r UnprotectedPrivilegedRule) Version() string { return UnprotectedPrivilegedRuleVersion }

func (r UnprotectedPrivilegedRule) Check(contract *bytecode.DecodedContract, blocks []bytecode.Block) []Finding {
	insts := contract.Instructions
	var findings []Finding
	for i, ins := range insts {
		if !opcodes.IsPrivileged(ins.Op) {
			continue
		}
		windowStartIdx := 0
		for j := i - 1; j >= 0; j-- {
			if insts[j].Op == opcodes.JUMPDEST {
				windowStartIdx = j + 1
				break
			}
		}
		var callerOff, eqOff int = -1, -1
		for j := windowStartIdx; j < i; j++ {
			switch insts[j].Op {
			case opcodes.CALLER:
				if callerOff < 0 {
					callerOff = insts[j].Offset
				}
			case opcodes.EQ:
				if eqOff < 0 {
					eqOff = insts[j].Offset
				}
			}
		}
		if callerOff >= 0 && eqOff >= 0 {
			continue // guarded
		}
		windowStartOff := 0
		if windowStartIdx < len(insts) {
			windowStartOff = insts[windowStartIdx].Offset
		}
		missing := "CALLER and EQ"
		if callerOff >= 0 {
			missing = "EQ"
		} else if eqOff >= 0 {
			missing = "CALLER"
		}
		findings = append(findings, Finding{
			RuleID:   r.ID(),
			Severity: SeverityHigh,
			Message:  fmt.Sprintf("%s at offset %d has no CALLER/EQ ownership guard in window starting at offset %d", opcodes.Lookup(ins.Op).Name, ins.Offset, windowStartOff),
			Evidence: []Evidence{{
				Description: "privileged instruction not dominated by a caller-identity equality check",
				Offsets:     []int{windowStartOff, ins.Offset},
				Details: map[string]any{
					"privileged_offset": ins.Offset,
					"privileged_opcode": "SELFDESTRUCT",
					"window_start":      windowStartOff,
					"missing_guard":     missing,
					"rule_version":      UnprotectedPrivilegedRuleVersion,
				},
			}},
		})
	}
	return findings
}
