package audit

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/highcumontoa/evm-bytecode-audit-go/bytecode"
	"github.com/highcumontoa/evm-bytecode-audit-go/rules"
)

// Analyzer performs single-contract analysis with a fixed rule set.
// Results are deterministic: identical input always yields an identical
// Report (InputHash, finding order and RuleVersions included).
type Analyzer struct {
	rules []rules.Rule
}

// NewAnalyzer builds an Analyzer with the given rules in their given order.
// Pass nil (or an empty slice) to use rules.DefaultRules().
func NewAnalyzer(rs []rules.Rule) *Analyzer {
	if len(rs) == 0 {
		rs = rules.DefaultRules()
	}
	cp := make([]rules.Rule, len(rs))
	copy(cp, rs)
	return &Analyzer{rules: cp}
}

// HashInput returns the lowercase hex SHA-256 of code.
func HashInput(code []byte) string {
	sum := sha256.Sum256(code)
	return hex.EncodeToString(sum[:])
}

// Analyze decodes and audits one contract. This method never returns nil
// and never panics on malformed input: malformed bytecode yields a Report
// with StatusRejected, so callers can rely on a complete conclusion.
func (a *Analyzer) Analyze(name string, code []byte) (report *Report) {
	h := HashInput(code)
	defer func() {
		if r := recover(); r != nil {
			report = &Report{
				Name:         name,
				InputHash:    h,
				ByteLen:      len(code),
				Status:       StatusError,
				RejectDetail: "analyzer panic",
				RuleVersions: a.ruleVersions(),
			}
		}
	}()

	base := Report{Name: name, InputHash: h, ByteLen: len(code), RuleVersions: a.ruleVersions()}

	decoded, err := bytecode.Decode(name, code)
	if err != nil {
		rj := err.(*bytecode.RejectError)
		base.Status = StatusRejected
		base.RejectKind = rj.Kind
		base.RejectDetail = rj.Error()
		return &base
	}

	blocks := bytecode.SplitBlocks(decoded)
	// Path-level well-formedness: the contract must be able to reach a
	// normal exit. This rejection is distinct from decode-time rejections
	// (RejectNoReachableExit) and runs before any rule.
	if err := bytecode.CheckReachableExit(decoded, blocks); err != nil {
		rj := err.(*bytecode.RejectError)
		base.Status = StatusRejected
		base.RejectKind = rj.Kind
		base.RejectDetail = rj.Error()
		return &base
	}
	for _, rule := range a.rules {
		base.Findings = append(base.Findings, rule.Check(decoded, blocks)...)
	}
	if base.Findings == nil {
		base.Findings = []rules.Finding{}
	}
	base.Status = StatusOK
	return &base
}

func (a *Analyzer) ruleVersions() []RuleVersion {
	out := make([]RuleVersion, 0, len(a.rules))
	for _, r := range a.rules {
		out = append(out, RuleVersion{RuleID: r.ID(), Version: r.Version()})
	}
	return out
}
