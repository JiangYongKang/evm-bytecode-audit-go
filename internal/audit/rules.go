// Package audit 提供基于规则的风险路径识别。
package audit

import (
	"fmt"
	"sort"
	"strings"

	"github.com/highcumontoa/evm-bytecode-audit-go/internal/evm"
)

// RuleID 标识一条审计规则。
type RuleID string

const (
	RuleReentrancy       RuleID = "REENTRANCY_STATE_WRITE_AFTER_CALL"
	RuleUncheckedCallRet RuleID = "UNCHECKED_CALL_RETURN"
	RuleUnguardedPriv    RuleID = "UNGUARDED_PRIVILEGED_OP"
)

// Evidence 是命中规则的可核对证据。
type Evidence struct {
	RuleID   RuleID
	BlockIdx int
	PCs      []int
	Detail   string
}

// String 以稳定格式渲染证据，便于日志与测试比对。
func (e Evidence) String() string {
	pcs := make([]string, len(e.PCs))
	for i, pc := range e.PCs {
		pcs[i] = fmt.Sprintf("0x%x", pc)
	}
	return fmt.Sprintf("%s block#%d pcs=[%s] %s", e.RuleID, e.BlockIdx, strings.Join(pcs, ","), e.Detail)
}

// Rule 定义一条审计规则。
type Rule interface {
	ID() RuleID
	Check(p *evm.Program) []Evidence
}

// DefaultRules 返回默认规则集。
func DefaultRules() []Rule {
	return []Rule{
		reentrancyRule{},
		uncheckedCallReturnRule{},
		unguardedPrivilegedRule{},
	}
}

// RulesetID 由规则 ID 列表派生，规则调整后 ID 变化，
// 使历史结论可按 (ruleset, 输入) 复现核对。
func RulesetID(rules []Rule) string {
	ids := make([]string, len(rules))
	for i, r := range rules {
		ids[i] = string(r.ID())
	}
	sort.Strings(ids)
	h := fnv1a(strings.Join(ids, "|"))
	return fmt.Sprintf("ruleset-%08x", h)
}

func fnv1a(s string) uint32 {
	var h uint32 = 2166136261
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619
	}
	return h
}

// reentrancyRule: 同一基本块内，可改状态的外部调用之后仍出现 SSTORE。
type reentrancyRule struct{}

func (reentrancyRule) ID() RuleID { return RuleReentrancy }

func (reentrancyRule) Check(p *evm.Program) []Evidence {
	var out []Evidence
	for bi, blk := range p.Blocks {
		lastCall := -1
		for _, in := range blk.Instrs {
			if in.Op.IsCall() && in.Op != evm.OpStaticcall {
				lastCall = in.PC
			}
			if in.Op == evm.OpSstore && lastCall >= 0 {
				out = append(out, Evidence{
					RuleID:   RuleReentrancy,
					BlockIdx: bi,
					PCs:      []int{lastCall, in.PC},
					Detail: fmt.Sprintf("SSTORE at pc=%d follows state-changing call at pc=%d in the same block",
						in.PC, lastCall),
				})
				lastCall = -1 // 同一调用只报告一次
			}
		}
	}
	return out
}

// uncheckedCallReturnRule: 调用返回值未在条件判断中使用即被丢弃或忽略。
type uncheckedCallReturnRule struct{}

func (uncheckedCallReturnRule) ID() RuleID { return RuleUncheckedCallRet }

func (uncheckedCallReturnRule) Check(p *evm.Program) []Evidence {
	var out []Evidence
	for bi, blk := range p.Blocks {
		for i, in := range blk.Instrs {
			if !in.Op.IsCall() {
				continue
			}
			checked := false
			discarded := false
			for j := i + 1; j < len(blk.Instrs); j++ {
				nx := blk.Instrs[j]
				switch {
				case nx.Op == evm.OpIszero:
					checked = true
				case nx.Op == evm.OpPop && j == i+1:
					discarded = true
				case nx.Op.IsCall():
					// 遇到下一条调用仍未校验
				}
				if checked || discarded || nx.Op.IsCall() {
					break
				}
			}
			if !checked {
				detail := fmt.Sprintf("return value of %s at pc=%d is not checked before block ends", in.Name(), in.PC)
				if discarded {
					detail = fmt.Sprintf("return value of %s at pc=%d is immediately POPped away", in.Name(), in.PC)
				}
				out = append(out, Evidence{
					RuleID:   RuleUncheckedCallRet,
					BlockIdx: bi,
					PCs:      []int{in.PC},
					Detail:   detail,
				})
			}
		}
	}
	return out
}

// unguardedPrivilegedRule: 特权指令前缺少 CALLER/ORIGIN 鉴权检查。
type unguardedPrivilegedRule struct{}

func (unguardedPrivilegedRule) ID() RuleID { return RuleUnguardedPriv }

func (unguardedPrivilegedRule) Check(p *evm.Program) []Evidence {
	var out []Evidence
	for bi, blk := range p.Blocks {
		guardSeen := false
		for _, in := range blk.Instrs {
			if in.Op == evm.OpCaller || in.Op == evm.OpOrigin {
				guardSeen = true
			}
			if in.Op.IsPrivileged() {
				if guardSeen {
					continue
				}
				out = append(out, Evidence{
					RuleID:   RuleUnguardedPriv,
					BlockIdx: bi,
					PCs:      []int{in.PC},
					Detail: fmt.Sprintf("privileged op %s at pc=%d has no CALLER/ORIGIN guard earlier in block",
						in.Name(), in.PC),
				})
			}
		}
	}
	return out
}
