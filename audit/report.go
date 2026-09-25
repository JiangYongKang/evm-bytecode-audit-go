// Package audit wires decoding, rule evaluation, caching and concurrent
// batch processing into a reproducible local audit pipeline.
package audit

import (
	"github.com/highcumontoa/evm-bytecode-audit-go/bytecode"
	"github.com/highcumontoa/evm-bytecode-audit-go/rules"
)

// Status is the per-contract analysis outcome.
type Status string

const (
	// StatusRejected means malformed input was refused (never analyzed).
	StatusRejected Status = "rejected"
	// StatusOK means the contract decoded successfully (findings may exist).
	StatusOK Status = "ok"
	// StatusError means analysis itself failed (non-bytecode error).
	StatusError Status = "error"
	// StatusTimeout means the per-contract deadline elapsed.
	StatusTimeout Status = "timeout"
)

// RuleVersion records which rule version produced a report, so historical
// conclusions can be re-derived after the rule set changes.
type RuleVersion struct {
	RuleID  rules.RuleID `json:"rule_id"`
	Version string       `json:"version"`
}

// Report is the deterministic conclusion for one contract.
type Report struct {
	Name         string              `json:"name"`
	InputHash    string              `json:"input_hash"`
	ByteLen      int                 `json:"byte_len"`
	Status       Status              `json:"status"`
	RejectKind   bytecode.RejectKind `json:"reject_kind,omitempty"`
	RejectDetail string              `json:"reject_detail,omitempty"`
	Findings     []rules.Finding     `json:"findings,omitempty"`
	RuleVersions []RuleVersion       `json:"rule_versions"`
}

// HasFinding reports whether the report contains a hit for ruleID.
func (r *Report) HasFinding(id rules.RuleID) bool {
	for _, f := range r.Findings {
		if f.RuleID == id {
			return true
		}
	}
	return false
}
