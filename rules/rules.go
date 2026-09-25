// Package rules contains deterministic risk-detection rules operating on
// decoded EVM bytecode and its basic blocks.
//
// Every rule has a stable RuleID and a semver-like Version string. Audit
// reports record both, so a finding produced today can still be re-derived
// after rule semantics evolve: use the reported rule id/version to check
// out the matching implementation and re-run it on the same InputHash.
package rules

import "github.com/highcumontoa/evm-bytecode-audit-go/bytecode"

// RuleID uniquely identifies a detection rule. IDs are stable identifiers;
// they are never reused for different semantics.
type RuleID string

const (
	// RuleReentrancy flags SSTORE after an external call in one block.
	RuleReentrancy RuleID = "REENTRANCY-STATE-WRITE-AFTER-CALL"
	// RuleUncheckedCall flags external calls whose success bit is POPped.
	RuleUncheckedCall RuleID = "UNCHECKED-CALL-RETURN"
	// RuleUnprotectedPrivileged flags unguarded SELFDESTRUCT.
	RuleUnprotectedPrivileged RuleID = "PRIVILEGED-UNPROTECTED-SELFDESTRUCT"
)

// Severity describes how risky a finding is.
type Severity string

const (
	SeverityHigh   Severity = "high"
	SeverityMedium Severity = "medium"
	SeverityLow    Severity = "low"
)

// Evidence is a checkable, machine-readable piece of proof for a finding.
// All offsets are byte offsets inside the original contract bytecode, so a
// reviewer can re-open the input and verify every cited instruction.
type Evidence struct {
	Description string         `json:"description"`
	Offsets     []int          `json:"offsets"`
	Details     map[string]any `json:"details,omitempty"`
}

// Finding is one rule hit for one contract. Findings from one rule are
// emitted in ascending offset order, keeping reports stable.
type Finding struct {
	RuleID   RuleID     `json:"rule_id"`
	Severity Severity   `json:"severity"`
	Message  string     `json:"message"`
	Evidence []Evidence `json:"evidence"`
}

// Rule is a single deterministic detection rule. Version must be bumped
// whenever semantics change.
type Rule interface {
	ID() RuleID
	Version() string
	Check(contract *bytecode.DecodedContract, blocks []bytecode.Block) []Finding
}

// DefaultRules returns the built-in rule set in stable order.
func DefaultRules() []Rule {
	return []Rule{
		ReentrancyRule{},
		UncheckedCallRule{},
		UnprotectedPrivilegedRule{},
	}
}
