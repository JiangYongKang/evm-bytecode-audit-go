package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"

	"github.com/highcumontoa/evm-bytecode-audit-go/internal/evm"
)

// Status 表示单个合约的审计结论状态。
type Status string

const (
	StatusClean    Status = "CLEAN"
	StatusFlagged  Status = "FLAGGED"
	StatusRejected Status = "REJECTED"
)

// Report 是单个合约的审计报告。
type Report struct {
	CodeHash  string
	Status    Status
	Reject    *evm.RejectError
	Findings  []Evidence
	RulesetID string
}

// CodeHashOf 计算字节码内容哈希，作为缓存键与报告标识。
func CodeHashOf(code []byte) string {
	sum := sha256.Sum256(code)
	return hex.EncodeToString(sum[:])
}

// Analyzer 对单个合约执行解码与规则检查。
type Analyzer struct {
	Rules []Rule
}

// NewAnalyzer 构造使用默认规则集的分析器。
func NewAnalyzer() *Analyzer { return &Analyzer{Rules: DefaultRules()} }

// Analyze 分析单个合约字节码；同一输入与规则集必得一致结论。
func (a *Analyzer) Analyze(code []byte) Report {
	rep := Report{
		CodeHash:  CodeHashOf(code),
		RulesetID: RulesetID(a.Rules),
	}
	prog, err := evm.Decode(code)
	if err != nil {
		var rej *evm.RejectError
		if errors.As(err, &rej) {
			rep.Status = StatusRejected
			rep.Reject = rej
			return rep
		}
		// 非预期错误也归类为拒绝，但原因可区分。
		rep.Status = StatusRejected
		rep.Reject = &evm.RejectError{Reason: "INTERNAL", Offset: -1, Detail: err.Error()}
		return rep
	}
	var findings []Evidence
	for _, r := range a.Rules {
		findings = append(findings, r.Check(prog)...)
	}
	// 排序保证结论与规则遍历顺序无关，输出稳定。
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].RuleID != findings[j].RuleID {
			return findings[i].RuleID < findings[j].RuleID
		}
		if findings[i].BlockIdx != findings[j].BlockIdx {
			return findings[i].BlockIdx < findings[j].BlockIdx
		}
		if len(findings[i].PCs) == 0 || len(findings[j].PCs) == 0 {
			return len(findings[i].PCs) < len(findings[j].PCs)
		}
		return findings[i].PCs[0] < findings[j].PCs[0]
	})
	rep.Findings = findings
	if len(findings) > 0 {
		rep.Status = StatusFlagged
	} else {
		rep.Status = StatusClean
	}
	return rep
}
